package server

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
)

// aclCacheTTL bounds how long a running server serves a stale access list.
// It matches the token cache in MutationAuthMiddleware because the two halves
// of the mutation gate should not answer a `bodega` command on different
// schedules: an operator who revokes a token and narrows admin_permit_cidr in
// the same minute expects both to land together.
const aclCacheTTL = 30 * time.Second

// aclSet is one resolved answer for all three CIDR lists, swapped whole so a
// request never reads a half-applied change: narrowing admin_permit_cidr while
// widening trusted_proxies must never be visible in that order.
type aclSet struct {
	admin   []*net.IPNet
	deny    []*net.IPNet
	trusted []*net.IPNet
	// trustedSet distinguishes "trust nobody" from "nobody said", exactly as
	// the config field does. See Server.trustedNetsSet.
	trustedSet bool
}

// aclNow returns the current set, refreshing it when the cache has aged out.
func (s *Server) aclNow() *aclSet {
	if set := s.aclCached(); set != nil {
		return set
	}
	s.aclMu.Lock()
	defer s.aclMu.Unlock()
	if set := s.aclCached(); set != nil {
		return set // another goroutine refreshed while we waited
	}
	return s.storeACLs(s.resolveACLs(context.Background()))
}

// aclCached returns the cached set, or nil when there is none or it is stale.
func (s *Server) aclCached() *aclSet {
	set := s.acl.Load()
	if set == nil {
		return nil
	}
	if time.Since(time.Unix(0, s.aclAt.Load())) >= aclCacheTTL {
		return nil
	}
	return set
}

func (s *Server) storeACLs(set *aclSet) *aclSet {
	s.acl.Store(set)
	s.aclAt.Store(time.Now().UnixNano())
	return set
}

// refreshACLs re-reads the lists regardless of cache age. SIGHUP calls it so
// `systemctl reload bodega` lands an ACL change at once rather than within the
// cache TTL.
func (s *Server) refreshACLs(ctx context.Context) {
	s.aclMu.Lock()
	defer s.aclMu.Unlock()
	s.storeACLs(s.resolveACLs(ctx))
}

// resolveACLs answers each list from the audit database where the database
// owns it, and from the config file where it does not. A list the database
// owns wins even when it is empty, which is what the acl_lists marker row is
// there to record.
//
// A list that fails to read or parse keeps its config file value rather than
// emptying: an empty admin list refuses every mutation and an empty deny list
// refuses none, so both directions of "fail open" and "fail closed" are worse
// than the last good answer.
func (s *Server) resolveACLs(ctx context.Context) *aclSet {
	set := &aclSet{
		admin:      s.adminNets,
		deny:       s.denyNets,
		trusted:    s.trustedNets,
		trustedSet: s.trustedNetsSet,
	}
	if s.auditDB == nil {
		return set
	}
	for _, list := range audit.ACLLists() {
		owned, err := s.auditDB.ACLSeeded(ctx, list)
		if err != nil {
			s.logger.Error("could not read acl list ownership; keeping the config file value",
				"list", list, "error", err)
			continue
		}
		if !owned {
			continue
		}
		cidrs, err := s.auditDB.ACLCIDRs(ctx, list)
		if err != nil {
			s.logger.Error("could not read acl list; keeping the config file value",
				"list", list, "error", err)
			continue
		}
		nets, bad := parseACLEntries(cidrs)
		if len(bad) > 0 {
			// Serve what parses. Discarding the whole list fell back to the
			// config file, which the database already owns and outranks, so
			// every later `bodega acl` change was inert while reporting
			// success: the admin list could be emptied in the table and the
			// admin reads still answered from the address just removed.
			s.logger.Error("unreadable entry in the acl table; it is skipped and the rest of the list is in force",
				"list", list, "skipped", strings.Join(bad, ","), "in_force", len(nets),
				"next_step", "bodega acl "+list+" remove --raw "+bad[0])
			if len(nets) == 0 && list == audit.ACLAdmin {
				// Every row was unreadable, so the admin list is now empty and
				// permits nobody: no mutation and none of the four admin reads,
				// from localhost included. `bodega acl` writes the database
				// directly and is the way back.
				s.logger.Error("every admin acl row is unreadable, so the admin list is empty and permits nobody",
					"next_step", "bodega acl admin add <cidr>")
			}
		}
		switch list {
		case audit.ACLAdmin:
			set.admin = nets
		case audit.ACLDeny:
			set.deny = nets
		case audit.ACLProxies:
			if nets == nil {
				nets = []*net.IPNet{}
			}
			set.trusted, set.trustedSet = nets, true
		}
	}
	return set
}

// AdminPermits answers the one question both halves of the admin gate ask:
// may this address reach the admin surface. MutationAuthMiddleware gates the
// mutation verbs with it and isAdminRequest gates the four admin read
// endpoints, so the two cannot drift apart on the same list again.
//
// An empty list permits nobody. It is an access control list an operator can
// empty (`bodega acl admin remove <last> --force`), never a statement that
// there is nothing to control: reading it as "no restriction" left /api/v1/audit
// and /api/v1/tokens open to every source address while every mutation was
// refused. A nil address is a client IP that would not parse, which is not a
// member of any network.
func AdminPermits(nets []*net.IPNet, ip net.IP) bool {
	if len(nets) == 0 || ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// parseAdminPermitCIDR parses the config file's admin list, and rejects one
// the operator wrote that bodega cannot use. Since AdminPermits reads an empty
// list as "permit nobody", discarding an unparseable list no longer opens the
// admin surface: it closes it, with the typo that did it named nowhere.
// Refusing to start says which entry, and where the live list is.
//
// Only a non-empty list is rejected. An absent one is answered by the localhost
// default in config.Load, and a list emptied through `bodega acl admin` is a
// deliberate act recorded in the audit database.
func parseAdminPermitCIDR(entries []string) ([]*net.IPNet, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	nets, err := ParseDenyList(entries)
	if err == nil && len(nets) > 0 {
		return nets, nil
	}
	why := "every entry is blank"
	if err != nil {
		why = err.Error()
	}
	return nil, fmt.Errorf(
		"admin_permit_cidr parses to nothing: %s\n"+
			"  An empty admin list permits nobody: every mutation and the /api/v1/audit,\n"+
			"  /api/v1/tokens, /api/v1/policies and /api/v1/config reads would answer 403.\n"+
			"  Fix the entry in %s, then start again.\n"+
			"  The live list:  bodega acl admin list",
		why, config.ConfigPath())
}

// adminNetsFunc, denyNetsFunc and trustedNetsFunc hand the middleware chain a
// live view. They are read per request, so the chain is built once and still
// sees a change made by `bodega acl` within aclCacheTTL.
func (s *Server) adminNetsFunc() NetsFunc { return func() []*net.IPNet { return s.aclNow().admin } }
func (s *Server) denyNetsFunc() NetsFunc  { return func() []*net.IPNet { return s.aclNow().deny } }

func (s *Server) trustedNetsFunc() NetsFunc {
	return func() []*net.IPNet {
		set := s.aclNow()
		if !set.trustedSet {
			return nil // ask RealIPMiddleware for the built-in default
		}
		return set.trusted
	}
}

// seedACLs copies the config file's lists into the audit database the first
// time a database sees them, and logs which source each list resolved from.
//
// Copied once, not read as a fallback forever: a list the database owns is
// answered from the database alone, and the config file's entry becomes inert.
// The alternative, a union with the file on every read, makes `bodega acl
// admin remove` unable to remove anything the file still names, which is the
// lockout in requirement 6 wearing the opposite sign.
func (s *Server) seedACLs(ctx context.Context) {
	if s.auditDB == nil {
		s.logger.Info("acl source", "lists", "all", "source", "config file", "detail", "no audit db")
		return
	}
	seeds := []struct {
		list    string
		entries []string
		// copy is false when the config file has no answer to copy. For
		// trusted_proxies that is the tri-state: absent means "take the
		// built-in default", and writing that default into the table would
		// freeze it as though an operator had chosen it.
		copy bool
	}{
		{audit.ACLAdmin, s.cfg.AdminPermitCIDR, len(s.cfg.AdminPermitCIDR) > 0},
		{audit.ACLDeny, s.cfg.DenyList, len(s.cfg.DenyList) > 0},
		{audit.ACLProxies, s.cfg.TrustedProxies, s.cfg.TrustedProxies != nil},
	}
	for _, sd := range seeds {
		owned, err := s.auditDB.ACLSeeded(ctx, sd.list)
		if err != nil {
			s.logger.Error("could not read acl list ownership; the config file value stays in force",
				"list", sd.list, "error", err)
			continue
		}
		if !owned {
			if !sd.copy {
				// Nothing to copy. For trusted_proxies that is the tri-state's
				// first case and the built-in default applies; for the other
				// two an absent list and an empty one mean the same thing.
				if sd.list == audit.ACLProxies {
					s.logger.Info("acl source", "list", sd.list, "source", "built-in default",
						"detail", "unset in both config and database")
				} else {
					s.logger.Info("acl source", "list", sd.list, "source", "config file",
						"detail", "empty", "entries", 0)
				}
				continue
			}
			if _, bad := parseACLEntries(sd.entries); len(bad) > 0 {
				// Copying it would mark the list database-owned with a row no
				// parser can read, and the refusal Start raises next says
				// nothing about the table. Leave the database unclaimed so
				// fixing the config file is the whole repair.
				s.logger.Error("not copying an unreadable acl list into the audit db; fix the config file and start again",
					"list", sd.list, "config_key", audit.ACLConfigKey(sd.list),
					"unreadable", strings.Join(bad, ","),
					"next_step", "correct "+audit.ACLConfigKey(sd.list)+" in "+config.ConfigPath())
				continue
			}
			if _, err := s.auditDB.SeedACL(ctx, sd.list, sd.entries, audit.CurrentActor()); err != nil {
				s.logger.Error("could not copy acl list from config into the audit db; the config file value stays in force",
					"list", sd.list, "error", err)
				continue
			}
			s.logger.Info("acl source", "list", sd.list, "source", "database",
				"detail", "copied from config file on this start", "entries", len(sd.entries))
			continue
		}
		dbCIDRs, err := s.auditDB.ACLCIDRs(ctx, sd.list)
		if err != nil {
			s.logger.Error("could not read acl list", "list", sd.list, "error", err)
			continue
		}
		s.logger.Info("acl source", "list", sd.list, "source", "database", "entries", len(dbCIDRs))
		if sd.copy && !sameCIDRs(sd.entries, dbCIDRs) {
			s.logger.Warn("acl config file and database disagree; the database wins and the file value is ignored",
				"list", sd.list, "config_key", audit.ACLConfigKey(sd.list),
				"config", strings.Join(sd.entries, ","), "database", strings.Join(dbCIDRs, ","),
				"next_step", "bodega acl "+sd.list+" list")
		}
	}
}

// parseACLEntries splits a list into the entries that parse and the raw text
// of the ones that do not. ParseDenyList answers all-or-nothing, which is the
// right shape for a config file the operator can edit and the wrong one for a
// table whose bad row can only be reached through the CLI.
func parseACLEntries(entries []string) ([]*net.IPNet, []string) {
	var nets []*net.IPNet
	var bad []string
	for _, e := range entries {
		one, err := ParseDenyList([]string{e})
		if err != nil {
			bad = append(bad, e)
			continue
		}
		nets = append(nets, one...)
	}
	return nets, bad
}

// sameCIDRs compares two lists as sets of parsed networks, so "10.0.0.1/8" in
// the config file does not read as a disagreement with the "10.0.0.0/8" the
// table stores.
func sameCIDRs(a, b []string) bool {
	norm := func(in []string) map[string]bool {
		out := make(map[string]bool, len(in))
		nets, err := ParseDenyList(in)
		if err != nil {
			for _, s := range in {
				out[s] = true
			}
			return out
		}
		for _, n := range nets {
			out[n.String()] = true
		}
		return out
	}
	na, nb := norm(a), norm(b)
	if len(na) != len(nb) {
		return false
	}
	for k := range na {
		if !nb[k] {
			return false
		}
	}
	return true
}
