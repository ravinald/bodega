package clientconf

import (
	"fmt"
	"math"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// gitConv is how Git 2.54.0 converts one configuration variable when a
// callback reads it: the git_config_* helper in config.c the callback calls,
// or the checks it runs itself.
type gitConv uint8

const (
	// gitBool is git_config_bool: dies on a value that is neither a truth
	// word nor an integer.
	gitBool gitConv = iota + 1
	// gitInt, gitSsize and gitUlong are git_config_int, git_config_ssize_t
	// and git_config_ulong: die on a value that is no number of that width.
	gitInt
	gitSsize
	gitUlong
	// gitString needs a value: a name with no = is config_error_nonbool,
	// which fails the whole read.
	gitString
	// gitPath is git_config_pathname: a value, and a ~user it can expand.
	gitPath
	// gitLevel is the zlib level of core.compression, core.loosecompression
	// and pack.compression: an int that is -1 or 0 through 9.
	gitLevel
	// gitWordOrBool is a variable that takes its own words and otherwise
	// goes to git_config_bool.
	gitWordOrBool
	// gitWord needs a value, one of its words in the case the callback
	// compares them in, where any other is an error.
	gitWord
	// gitAbbrev is core.abbrev.
	gitAbbrev
	// gitComment is core.commentchar and core.commentstring.
	gitComment
	// gitColor is a color git parses with color_parse, and gitBackend
	// http.sslbackend, which git accepts only when the curl it was built
	// against carries that backend. This port holds neither, so a value for
	// one is refused as not interpreted.
	gitColor
	gitBackend
	// gitAny is a variable git fetch and git clone read, or that Git
	// documents in a section they read, and convert nothing in: no value
	// stops either command.
	gitAny
	// gitShared is core.sharedrepository, read by git_config_perm.
	gitShared
	// gitProtocol is protocol.allow and protocol.https.allow.
	gitProtocol
	// gitFsck is fetch.fsck.<msg-id>.
	gitFsck
	// The rest are refused as not interpreted for any value past the form
	// each names: a refspec outside one glob per side, which git also matches
	// against the remote's refs; a remote name outside plain characters; an
	// event that has a configured hook run a command; and a URL or helper for
	// the remote git clone itself names.
	gitRefspec
	gitRemoteName
	gitHookEvent
	gitCloneRemote
)

type gitVar struct {
	conv gitConv
	// words are the values gitWordOrBool and gitWord take, and fold whether
	// the callback compares them with strcasecmp.
	words []string
	fold  bool
	// need is a callback that returns config_error_nonbool for a name with
	// no =, whatever it converts a value with, and nonEmpty one that refuses
	// the empty string as well.
	need, nonEmpty bool
	// ranged holds a number to [lo, hi] past its type's width.
	ranged bool
	lo, hi int64
	// bare is a variable git reads through a lookup that takes a name with no
	// = as no setting, where the conversion alone would refuse it.
	bare bool
	// later marks a conversion git runs only once the command reaches a state
	// a fetch from a public repository may not: asking for credentials,
	// recursing into submodules, fetching a promised object, running a filter.
	// It is refused all the same, and no native run is held against it.
	later bool
}

// gitHTTPVars is http_options in http.c at Git 2.54.0 (lines 392-602), the
// callback git-remote-https converts every http variable with before its
// first request, keyed by the name after "http.". http.delegation is read as
// git built against curl 7.22.0 or later reads it. What http_init does with
// a converted value afterwards is not here: it parses http.proxy as a URL
// only once a request needs it.
var gitHTTPVars = map[string]gitVar{
	"version": {conv: gitString}, "sslverify": {conv: gitBool}, "sslcipherlist": {conv: gitString},
	"sslversion": {conv: gitString}, "sslcert": {conv: gitPath}, "sslcerttype": {conv: gitString},
	"sslkey": {conv: gitPath}, "sslkeytype": {conv: gitString}, "sslcapath": {conv: gitPath},
	"sslcainfo": {conv: gitPath}, "sslcertpasswordprotected": {conv: gitBool}, "ssltry": {conv: gitBool},
	"schannelcheckrevoke": {conv: gitBool}, "schannelusesslcainfo": {conv: gitBool},
	"minsessions": {conv: gitInt}, "maxrequests": {conv: gitInt}, "lowspeedlimit": {conv: gitInt},
	"lowspeedtime": {conv: gitInt}, "noepsv": {conv: gitBool}, "proxy": {conv: gitString},
	"proxyauthmethod": {conv: gitString}, "proxysslcert": {conv: gitString}, "proxysslkey": {conv: gitString},
	"proxysslcainfo": {conv: gitString}, "proxysslcertpasswordprotected": {conv: gitBool},
	"cookiefile": {conv: gitPath}, "savecookies": {conv: gitBool}, "postbuffer": {conv: gitSsize},
	"useragent": {conv: gitString}, "emptyauth": {conv: gitWordOrBool, words: []string{"auto"}},
	"delegation": {conv: gitString}, "pinnedpubkey": {conv: gitPath}, "extraheader": {conv: gitString},
	"curloptresolve": {conv: gitString}, "followredirects": {conv: gitWordOrBool, words: []string{"initial"}},
	// An unknown http.proactiveauth is a warning.
	"proactiveauth": {conv: gitString}, "keepaliveidle": {conv: gitInt}, "keepaliveinterval": {conv: gitInt},
	"keepalivecount": {conv: gitInt}, "retryafter": {conv: gitInt}, "maxretries": {conv: gitInt},
	"maxretrytime": {conv: gitInt}, "sslbackend": {conv: gitBackend},
}

// gitDefaultVars is git_default_config in environment.c at Git 2.54.0 (lines
// 665-712) with the callbacks it hands a variable to: git_default_core_config
// (301-524), git_ident_config and set_ident in ident.c, and the i18n, branch,
// push, attr and sparse callbacks beside it. http_options ends by calling it
// for every variable that is not its own, and nearly every git command reads
// its configuration through it too. core.eol, core.whitespace's rule words,
// core.fsync's component names and an unknown core.fsyncmethod fail nothing
// in git, and platform_core_config is Windows's alone.
var gitDefaultVars = map[string]gitVar{
	"core.filemode": {conv: gitBool}, "core.trustctime": {conv: gitBool},
	"core.checkstat": {conv: gitWord, words: []string{"default", "minimal"}, fold: true},
	"core.quotepath": {conv: gitBool}, "core.symlinks": {conv: gitBool}, "core.ignorecase": {conv: gitBool},
	"core.attributesfile": {conv: gitPath}, "core.bare": {conv: gitBool}, "core.ignorestat": {conv: gitBool},
	"core.abbrev":           {conv: gitAbbrev},
	"core.disambiguate":     {conv: gitWord, words: []string{"none", "commit", "committish", "tree", "treeish", "blob"}, fold: true},
	"core.loosecompression": {conv: gitLevel}, "core.compression": {conv: gitLevel},
	"core.autocrlf":               {conv: gitWordOrBool, words: []string{"input"}, fold: true},
	"core.safecrlf":               {conv: gitWordOrBool, words: []string{"warn"}, fold: true},
	"core.checkroundtripencoding": {conv: gitString}, "core.editor": {conv: gitString},
	"core.commentchar": {conv: gitComment}, "core.commentstring": {conv: gitComment},
	"core.askpass": {conv: gitString}, "core.excludesfile": {conv: gitPath},
	"core.whitespace": {conv: gitString}, "core.fsync": {conv: gitString}, "core.fsyncmethod": {conv: gitString},
	"core.fsyncobjectfiles": {conv: gitBool}, "core.lockfilepid": {conv: gitBool},
	"core.createobject":   {conv: gitWord, words: []string{"rename", "link"}},
	"core.sparsecheckout": {conv: gitBool}, "core.sparsecheckoutcone": {conv: gitBool},
	"core.precomposeunicode": {conv: gitBool}, "core.protecthfs": {conv: gitBool}, "core.protectntfs": {conv: gitBool},
	"user.useconfigonly": {conv: gitBool}, "user.name": {conv: gitString}, "user.email": {conv: gitString},
	"author.name": {conv: gitString}, "author.email": {conv: gitString},
	"committer.name": {conv: gitString}, "committer.email": {conv: gitString},
	"i18n.commitencoding": {conv: gitString}, "i18n.logoutputencoding": {conv: gitString},
	"branch.autosetupmerge":  {conv: gitWordOrBool, words: []string{"always", "inherit", "simple"}},
	"branch.autosetuprebase": {conv: gitWord, words: []string{"never", "local", "remote", "always"}},
	"push.default":           {conv: gitWord, words: []string{"nothing", "matching", "simple", "upstream", "tracking", "current"}},
	"attr.tree":              {conv: gitString},
	"color.advice":           {conv: gitWordOrBool, words: []string{"never", "always", "auto"}, fold: true},
	"color.advice.reset":     {conv: gitColor}, "color.advice.hint": {conv: gitColor},
	"pager.color": {conv: gitBool}, "color.pager": {conv: gitBool},
	"pack.packsizelimit": {conv: gitUlong}, "pack.compression": {conv: gitLevel},
	"sparse.expectfilesoutsideofpatterns": {conv: gitBool},
}

// gitAdvice is advice_setting in advice.c at Git 2.54.0, lowercased: the
// advice.* names git_default_advice_config converts with git_config_bool. Any
// other advice.* name is ignored.
var gitAdvice = strings.Fields(`addembeddedrepo addemptypathspec addignoredfile ambiguousfetchrefspec amworkdir
	checkoutambiguousremotebranchname commitbeforemerge defaultbranchname detachedhead diverging
	fetchremoteheadwarn fetchshowforcedupdates forcedeletebranch graftfiledeprecated ignoredhook
	implicitidentity mergeconflict nestedtag objectnamewarning pushalreadyexists pushfetchfirst
	pushneedsforce pushnonffcurrent pushnonffmatching pushrefneedsupdate pushunqualifiedrefname
	pushupdaterejected pushnonfastforward rebasetodoerror refsyntax resetnorefresh resolveconflict rmhints
	sequencerinuse setupstreamfailure skippedcherrypicks sparseindexexpanded statusaheadbehindwarning
	statushints statusuoption submodulesnotupdated submodulealternateerrorstrategydie
	submodulemergeconflict suggestdetachinghead updatesparsepath waitingforeditor worktreeaddorphan`)

// gitOpVars holds the variables git fetch and git clone convert at Git
// 2.54.0 beyond git_default_config and http_options, each under its key in
// lower case, with * for a subsection: git_fetch_config and cmd_fetch in
// builtin/fetch.c (lines 109-180 and 2440-2460), git_clone_config and
// cmd_clone in builtin/clone.c, handle_config in remote.c for remote.*,
// branch.* and url.*, prepare_repo_settings in repo-settings.c,
// fetch_pack_config in fetch-pack.c, the index-pack and unpack-objects they
// run, the checkout a clone ends with (unpack-trees.c, read-cache.c and
// read_convert_config in convert.c), transport.c's protocol checks,
// submodule-config.c, hook.c, and trace2's tr2_cfg.c. Beside them are the
// names Git documents in the same sections that neither command converts,
// as gitAny, so that a name in none of the lists is one this port has no
// reading of.
//
// TestGitOperationVarsMatchNativeGit runs both commands under each variable
// and value and compares git's answer with the table's.
var gitOpVars = func() map[string]gitVar {
	m := map[string]gitVar{}
	set := func(v gitVar, names string) {
		for _, name := range strings.Fields(names) {
			m[name] = v
		}
	}
	set(gitVar{conv: gitString}, `branch.*.merge branch.*.pushremote branch.*.remote remote.*.followremotehead
		remote.*.proxyauthmethod remote.*.pushurl remote.*.receivepack remote.*.serveroption remote.*.tagopt
		remote.*.uploadpack remote.*.proxy remote.*.partialclonefilter remote.*.url remote.*.vcs remote.pushdefault
		trace2.configparams trace2.destinationdebug trace2.envvars trace2.eventbrief trace2.eventnesting
		trace2.eventtarget trace2.maxfiles trace2.normalbrief trace2.normaltarget trace2.perfbrief trace2.perftarget
		url.*.pushinsteadof core.untrackedcache fetch.bundleuri transfer.hiderefs filter.*.clean
		filter.*.smudge hook.*.command hook.*.enabled init.defaultobjectformat init.defaultrefformat`)
	set(gitVar{conv: gitString, nonEmpty: true}, `url.*.insteadof`)
	set(gitVar{conv: gitBool}, `core.prefersymlinkrefs feature.experimental feature.manyfiles remote.*.mirror remote.*.prune
		remote.*.prunetags remote.*.skipdefaultupdate remote.*.skipfetchall remote.*.promisor
		commitgraph.readchangedpaths core.commitgraph core.multipackindex core.usereplacerefs fetch.writecommitgraph
		gc.writecommitgraph index.skiphash index.sparse pack.readreverseindex pack.usebitmapboundarytraversal
		pack.usepathwalk pack.usesparse fetch.all fetch.prune fetch.prunetags fetch.showforcedupdates submodule.recurse
		core.warnambiguousrefs gc.autodetach maintenance.auto maintenance.autodetach fetch.fsckobjects
		transfer.fsckobjects repack.usedeltabaseoffset transfer.advertisesid index.recordendofindexentries index.threads
		pack.writereverseindex transfer.bundleuri clone.filtersubmodules clone.rejectshallow
		init.defaultsubmodulepathconfig`)
	set(gitVar{conv: gitInt}, `checkout.thresholdforparallelism checkout.workers core.filesreflocktimeout
		core.packedrefstimeout fetch.unpacklimit transfer.unpacklimit commitgraph.changedpathsversion
		commitgraph.generationversion index.version`)
	set(gitVar{conv: gitInt, ranged: true, hi: math.MaxInt32}, `fetch.parallel submodule.fetchjobs pack.threads core.maxtreedepth`)
	set(gitVar{conv: gitInt, ranged: true, hi: 2}, `pack.indexversion protocol.version`)
	set(gitVar{conv: gitUlong}, `core.deltabasecachelimit core.packedgitlimit core.packedgitwindowsize core.bigfilethreshold`)
	set(gitVar{conv: gitPath}, `core.hookspath`)
	set(gitVar{conv: gitPath, bare: true}, `init.templatedir`)
	set(gitVar{conv: gitWord, words: []string{"skipping", "noop", "consecutive", "default"}, fold: true}, `fetch.negotiationalgorithm`)
	set(gitVar{conv: gitWord, words: []string{"full", "compact"}, fold: true}, `fetch.output`)
	set(gitVar{conv: gitWord, words: []string{"allow", "warn", "die"}}, `transfer.credentialsinurl`)
	set(gitVar{conv: gitWordOrBool, words: []string{"on-demand"}}, `fetch.recursesubmodules`)
	set(gitVar{conv: gitWordOrBool, words: []string{"always"}, fold: true, need: true}, `core.logallrefupdates`)
	set(gitVar{conv: gitShared}, `core.sharedrepository`)
	set(gitVar{conv: gitProtocol}, `protocol.allow`)
	set(gitVar{conv: gitRefspec}, `remote.*.fetch remote.*.push`)
	set(gitVar{conv: gitRemoteName}, `clone.defaultremotename`)
	set(gitVar{conv: gitHookEvent}, `hook.*.event`)
	// A clone of a repository with submodules, a partial clone, and a
	// checkout through a filter driver.
	set(gitVar{conv: gitString, later: true}, `submodule.*.url submodule.*.branch submodule.*.update submodule.*.ignore filter.*.process`)
	set(gitVar{conv: gitBool, later: true}, `submodule.*.active submodule.propagatebranches promisor.quiet filter.*.required`)
	set(gitVar{conv: gitWordOrBool, words: []string{"on-demand"}, later: true}, `submodule.*.fetchrecursesubmodules`)
	set(gitVar{conv: gitAny}, `core.alternaterefscommand core.alternaterefsprefixes core.eol core.fsmonitor core.fsmonitorhookversion
		core.gitproxy core.hidedotfiles core.notesref core.pager core.preloadindex core.repositoryformatversion
		core.splitindex core.sshcommand core.unsetenvvars core.worktree fetch.bundlecreationtoken branch.*.description
		branch.*.mergeoptions branch.*.rebase branch.sort transfer.advertiseobjectinfo submodule.active
		submodule.alternateerrorstrategy submodule.alternatelocation submodule.*.gitdir init.defaultbranch
		pack.allowpackreuse pack.deltacachelimit pack.deltacachesize pack.depth pack.island
		pack.islandcore pack.preferbitmaptips pack.usebitmaps pack.window pack.windowmemory pack.writebitmaphashcache
		pack.writebitmaplookuptable index.recordoffsettable commitgraph.changedpaths commitgraph.maxnewfilters
		checkout.defaultremote checkout.guess user.signingkey push.autosetupremote push.followtags push.gpgsign
		push.negotiate push.pushoption push.recursesubmodules push.usebitmaps push.useforceifincludes
		gc.*.reflogexpire gc.*.reflogexpireunreachable gc.aggressivedepth gc.aggressivewindow gc.auto
		gc.autopacklimit gc.bigpackthreshold gc.cruftpacks gc.logexpiry gc.maxcruftsize gc.packrefs gc.pruneexpire
		gc.recentobjectshook gc.reflogexpire gc.reflogexpireunreachable gc.repackfilter gc.repackfilterto
		gc.rerereresolved gc.rerereunresolved gc.worktreepruneexpire maintenance.*.enabled maintenance.*.schedule
		maintenance.*.auto maintenance.*.splitfactor maintenance.*.batchsize maintenance.repo maintenance.strategy
		repack.cruftdepth repack.cruftthreads repack.cruftwindow repack.cruftwindowmemory
		repack.midxmustcontaincruft repack.packkeptobjects repack.updateserverinfo repack.usedeltaislands
		repack.writebitmaps promisor.acceptfromserver promisor.advertise promisor.checkfields promisor.sendfields
		promisor.storefields protocol.*.allow`)
	return m
}()

// gitOpSections are the sections gitOpVars and gitDefaultVars answer for
// whole: a name there that neither holds is refused as not interpreted. http
// and advice are held whole by gitHTTPVars and gitAdvice, each the complete
// list of one callback, and credential by lookup itself, so an unknown name in
// one of those is a name git does not read.
var gitOpSections = strings.Fields(`core fetch remote branch url transfer protocol submodule clone init pack index
	feature commitgraph checkout filter hook trace2 attr author committer user i18n push sparse gc maintenance
	repack promisor`)

// gitFsckIDs is FOREACH_FSCK_MSG_ID in fsck.h at Git 2.54.0, each id as a
// configuration key names it. The first two are the FATAL ids, which
// fsck_set_msg_type lets no value but error stand for.
var gitFsckIDs = strings.Fields(`nulinheader unterminatedheader badheadercontinuation baddate baddateoverflow bademail
	badgpgsig badheadtarget badname badobjectsha1 badpackedrefentry badpackedrefheader badparentsha1
	badreferentname badrefcontent badreffiletype badrefname badrefoid badtimezone badtree badtreesha1 badtype
	duplicateentries gitattributesblob gitattributeslarge gitattributeslinelength gitattributesmissing
	gitmodulesblob gitmoduleslarge gitmodulesmissing gitmodulesname gitmodulespath gitmodulessymlink
	gitmodulesupdate gitmodulesurl missingauthor missingcommitter missingemail missingnamebeforeemail
	missingobject missingspacebeforedate missingspacebeforeemail missingtag missingtagentry missingtree
	missingtype missingtypeentry multipleauthors packedrefentrynotterminated packedrefunsorted treenotsorted
	unknowntype zeropaddeddate badreftabletablename emptyname fullpathname hasdot hasdotdot hasdotgit
	largepathname nullsha1 nulincommit zeropaddedfilemode badfilemode badtagname emptypackedrefsfile
	gitattributessymlink gitignoresymlink gitmodulesparse mailmapsymlink missingtaggerentry refmissingnewline
	symlinkref symreftargetisnotaref trailingrefcontent extraheaderentry`)

// lookup is the conversion git fetch and git clone apply to e, in the
// processes that run it: the command itself, the git-remote-https it starts,
// and the index-pack and checkout behind them. http_init's
// urlmatch_config_entry routes a variable of the http section to http_options
// under the name after its last dot, and every command hands the rest to
// git_default_config and to its own callbacks, which gitOpVars holds.
//
// known is false for a name in a section those tables answer for whole that
// none of them holds: a variable this port has no reading of.
//
// git converts an [http "<url>"] variable only when the URL matches the
// remote and no closer match came before it. Which remote is not known here,
// so every http variable is converted: a value git would die on under a URL
// it never fetches from is refused all the same, which errs toward refusing.
// credential.<url>.* is read the same way.
func (e GitEntry) lookup() (name string, v gitVar, ok, known bool) {
	if e.Section == "http" {
		name = "http." + e.Name
		if v, ok = gitHTTPVars[e.Name]; ok {
			return name, v, true, true
		}
		if e.Subsection != "" {
			return name, v, false, true
		}
	}
	name = e.Key()
	if v, ok = gitDefaultVars[name]; ok {
		return name, v, true, true
	}
	if e.Section == "advice" && e.Subsection == "" {
		for _, k := range gitAdvice {
			if k == e.Name {
				return name, gitVar{conv: gitBool}, true, true
			}
		}
	}
	switch {
	case e.Section == "credential":
		// credential_config_callback in credential.c (lines 105-140) refuses
		// a name with no = before it looks at which name it is.
		switch e.Name {
		case "usehttppath", "sanitizeprompt", "protectprotocol":
			return name, gitVar{conv: gitBool, need: true, later: true}, true, true
		}
		return name, gitVar{conv: gitAny, need: true, later: true}, true, true
	case e.Section == "fetch" && e.Subsection == "fsck":
		if e.Name == "skiplist" {
			return name, gitVar{conv: gitPath}, true, true
		}
		return name, gitVar{conv: gitFsck}, true, true
	case e.Section == "protocol" && e.Subsection == "https" && e.Name == "allow":
		return name, gitVar{conv: gitProtocol}, true, true
	case e.Section == "remote" && e.Subsection == "origin" && (e.Name == "url" || e.Name == "vcs"):
		return name, gitVar{conv: gitCloneRemote}, true, true
	}
	key := name
	if e.Subsection != "" {
		key = e.Section + ".*." + e.Name
	}
	if v, ok = gitOpVars[key]; ok {
		return name, v, true, true
	}
	return name, v, false, !slices.Contains(gitOpSections, e.Section)
}

// GitConvertError is the first variable of a git configuration file that
// stops git fetch or git clone while git converts it, or that doctor cannot
// tell so of, as the line it stands on and a message: git's own for a value
// git dies on, and one saying doctor does not interpret the variable
// otherwise. 0 and "" for a file whose every variable converts. The file must
// already load: ParseGitConfig's BadLine comes first, as git's own parse does.
//
// It ports what both commands convert before and while they fetch: each runs
// git_default_config and its own callbacks over every variable, the
// git-remote-https it starts reads the configuration again through
// urlmatch_config_entry with http_options, and each calls git_config_bool,
// git_config_int and their kin, which die on a value of the wrong type, or
// returns an error, which git_config dies on. A variable in a section those
// callbacks read that this port holds no conversion for is refused rather
// than passed: a callback missing here would otherwise certify whatever it
// reads. A variable in any other section is one neither command converts.
func GitConvertError(cfg GitConfig) (line int, msg string) {
	for _, e := range cfg.Entries {
		name, v, ok, known := e.lookup()
		if !known {
			return e.Line, fmt.Sprintf("'%s' is in a section git fetch and git clone read and is no variable Git 2.54.0 documents there, so what git does with it is one doctor does not interpret", name)
		}
		if !ok {
			continue
		}
		if msg, _ := v.refuses(name, e.Value, e.HasValue); msg != "" {
			return e.Line, msg
		}
	}
	return 0, ""
}

// gitGlobRefspec is a refspec with one * on each side under refs/, in the
// characters every ref name may hold.
var gitGlobRefspec = regexp.MustCompile(`^\+?refs/[A-Za-z0-9_/-]*\*[A-Za-z0-9_/-]*:refs/[A-Za-z0-9_/-]*\*[A-Za-z0-9_/-]*$`)

var gitPlainRemoteName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// refuses is why git fetch or git clone does not run with value for the
// variable name, or "". own is true for a refusal that is doctor's and not
// git's: a value this port does not interpret.
func (v gitVar) refuses(name, value string, has bool) (msg string, own bool) {
	if v.bare && !has {
		return "", false
	}
	if (v.need || v.nonEmpty) && !has {
		return fmt.Sprintf("missing value for '%s'", name), false
	}
	if v.nonEmpty && value == "" {
		return fmt.Sprintf("'%s' is set to the empty string, which git refuses", name), false
	}
	unread := func(format string, args ...any) (string, bool) {
		return fmt.Sprintf("'%s' %s, which doctor does not interpret", name, fmt.Sprintf(format, args...)), true
	}
	switch v.conv {
	case gitAny:
		return "", false
	case gitShared:
		// git_config_perm in setup.c: its words, then an octal number, of
		// which 0, 1 and 2 are the old spellings and any other a file mode it
		// checks, then git_config_bool.
		switch value {
		case "umask", "group", "all", "world", "everybody":
			return "", false
		}
		if !has {
			return "", false
		}
		if n, err := strconv.ParseInt(strings.TrimLeft(value, " \t\n\v\f\r"), 8, 64); err == nil {
			if n < 0 || n > 2 {
				return unread("is the file mode %s, which git checks before it accepts it", value)
			}
			return "", false
		}
		if !gitBoolish(value) {
			return fmt.Sprintf("bad boolean config value '%s' for '%s'", value, name), false
		}
		return "", false
	case gitProtocol:
		// parse_protocol_config and is_transport_allowed in transport.c.
		switch {
		case !has:
			return fmt.Sprintf("missing value for '%s'", name), false
		case strings.EqualFold(value, "always"), strings.EqualFold(value, "user"):
			return "", false
		case strings.EqualFold(value, "never"):
			return fmt.Sprintf("transport 'https' not allowed ('%s' is never)", name), false
		}
		return fmt.Sprintf("unknown value for config '%s': %s", name, value), false
	case gitFsck:
		// fetch_pack_fsck_config in fetch-pack.c over fsck_set_msg_type in
		// fsck.c: an id fsck does not know is a warning.
		if !has {
			return fmt.Sprintf("missing value for '%s'", name), false
		}
		id := name[strings.LastIndex(name, ".")+1:]
		at := slices.Index(gitFsckIDs, id)
		switch {
		case at < 0:
			return "", false
		case id == "largepathname" && strings.Contains(value, ":"):
			return unread("carries a length after its message type")
		case value != "error" && value != "warn" && value != "ignore":
			return fmt.Sprintf("Unknown fsck message type: '%s'", value), false
		case at < 2 && value != "error":
			return fmt.Sprintf("Cannot demote %s to %s", id, value), false
		}
		return "", false
	case gitRefspec:
		switch {
		case !has:
			return fmt.Sprintf("missing value for '%s'", name), false
		case !gitGlobRefspec.MatchString(value) || strings.Contains(value, "//"):
			return unread("is a refspec git dies on when it is malformed or names a ref the remote lacks, and it is not of the form refs/<pattern>:refs/<pattern> with one * in each pattern")
		}
		return "", false
	case gitRemoteName:
		switch {
		case !has:
			return fmt.Sprintf("missing value for '%s'", name), false
		case !gitPlainRemoteName.MatchString(value):
			return unread("is a remote name git clone checks as a ref name, and it holds more than letters, digits, - and _")
		}
		return "", false
	case gitHookEvent:
		switch {
		case !has:
			return fmt.Sprintf("missing value for '%s'", name), false
		case value != "":
			return unread("has git run a configured command at the event %s, and a fetch or clone stops when one it runs fails", value)
		}
		return "", false
	case gitCloneRemote:
		if !has {
			return fmt.Sprintf("missing value for '%s'", name), false
		}
		return unread("configures the remote git clone names origin for every repository, and git clone then fetches from what this file names ahead of the URL it was given")
	}
	msg = v.converts(name, value, has)
	if msg == "" && v.ranged {
		// The callbacks that hold a number to a range read it as an int
		// first, so the conversion above has already passed.
		if n, why := gitNumber(value, has, big.NewInt(math.MinInt32), big.NewInt(math.MaxInt32)); why == "" && (n.Int64() < v.lo || n.Int64() > v.hi) {
			msg = fmt.Sprintf("'%s' is %d, and git accepts %d through %d", name, n.Int64(), v.lo, v.hi)
		}
	}
	return msg, msg != "" && (v.conv == gitColor || v.conv == gitBackend || strings.Contains(msg, "doctor does not look up"))
}

// converts is the conversion of one of the git_config_* helpers.
func (v gitVar) converts(name, value string, has bool) string {
	missing := fmt.Sprintf("missing value for '%s'", name)
	badBool := func() string {
		if has && !gitBoolish(value) {
			return fmt.Sprintf("bad boolean config value '%s' for '%s'", value, name)
		}
		return ""
	}
	word := func() bool {
		for _, w := range v.words {
			if has && (value == w || v.fold && strings.EqualFold(value, w)) {
				return true
			}
		}
		return false
	}
	number := func(min, max *big.Int) (*big.Int, string) {
		n, why := gitNumber(value, has, min, max)
		if why != "" {
			return nil, fmt.Sprintf("bad numeric config value '%s' for '%s': %s", value, name, why)
		}
		return n, ""
	}
	i32 := func() (*big.Int, string) { return number(big.NewInt(math.MinInt32), big.NewInt(math.MaxInt32)) }
	switch v.conv {
	case gitBool:
		return badBool()
	case gitInt:
		_, msg := i32()
		return msg
	case gitSsize:
		_, msg := number(big.NewInt(math.MinInt64), big.NewInt(math.MaxInt64))
		return msg
	case gitUlong:
		// git_parse_unsigned refuses a '-' anywhere before strtoumax can
		// wrap it.
		if strings.Contains(value, "-") {
			return fmt.Sprintf("bad numeric config value '%s' for '%s': invalid unit", value, name)
		}
		_, msg := number(new(big.Int), new(big.Int).SetUint64(math.MaxUint64))
		return msg
	case gitString:
		if !has {
			return missing
		}
	case gitPath:
		if !has {
			return missing
		}
		// interpolate_path asks the password database for ~user, which
		// doctor does not.
		path := strings.TrimPrefix(value, ":(optional)")
		if user, _, _ := strings.Cut(path, "/"); strings.HasPrefix(user, "~") && user != "~" {
			return fmt.Sprintf("'%s' for '%s' names the home directory of the account %s, which git dies on when no such account exists and doctor does not look up", value, name, user[1:])
		}
	case gitLevel:
		n, msg := i32()
		if msg != "" {
			return msg
		}
		if n.Int64() < -1 || n.Int64() > 9 {
			return fmt.Sprintf("bad zlib compression level %d for '%s'", n.Int64(), name)
		}
	case gitWordOrBool:
		if !word() {
			return badBool()
		}
	case gitWord:
		if !has {
			return missing
		}
		if !word() {
			return fmt.Sprintf("invalid value for '%s': '%s'", name, value)
		}
	case gitAbbrev:
		if !has {
			return missing
		}
		// "auto", or a word git_parse_maybe_bool_text reads as false.
		if strings.EqualFold(value, "auto") || value == "" || strings.EqualFold(value, "false") || strings.EqualFold(value, "no") || strings.EqualFold(value, "off") {
			return ""
		}
		n, msg := i32()
		if msg != "" {
			return msg
		}
		if n.Int64() < 4 {
			return fmt.Sprintf("abbrev length out of range: %d", n.Int64())
		}
	case gitComment:
		switch {
		case !has:
			return missing
		case value == "":
			return name + " must have at least one character"
		case !strings.EqualFold(value, "auto") && strings.Contains(value, "\n"):
			return name + " cannot contain newline"
		}
	case gitColor:
		if !has {
			return missing
		}
		return fmt.Sprintf("'%s' is a color git parses and dies on when it is malformed, which doctor does not interpret", name)
	case gitBackend:
		if has {
			return fmt.Sprintf("'%s' selects the TLS library git verifies with, and git dies on one its curl was not built with, which doctor does not interpret", name)
		}
	}
	return ""
}

// gitBoolish is git_parse_maybe_bool in parse.c for a variable with a value:
// "", a truth word in any case, or anything git_parse_int reads.
func gitBoolish(value string) bool {
	switch strings.ToLower(value) {
	case "", "true", "yes", "on", "false", "no", "off":
		return true
	}
	_, why := gitNumber(value, true, big.NewInt(math.MinInt32), big.NewInt(math.MaxInt32))
	return why == ""
}

// gitNumber is git_parse_signed and git_parse_unsigned in parse.c: strtoimax
// in base 0 (white space, a sign, then 0x hex, 0 octal or decimal digits),
// then nothing or one of k, m and g in either case as a power of 1024, the
// product held to [min, max]. why is the phrase die_bad_number ends on:
// "invalid unit" for a value that is no number or ends in anything else,
// "out of range" for one past the type. A variable with no value is the
// first.
func gitNumber(value string, has bool, min, max *big.Int) (n *big.Int, why string) {
	const unit, rng = "invalid unit", "out of range"
	if !has || value == "" {
		return nil, unit
	}
	s := strings.TrimLeft(value, " \t\n\v\f\r")
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg, s = s[0] == '-', s[1:]
	}
	hex := func(c byte) bool { return c >= '0' && c <= '9' || c|0x20 >= 'a' && c|0x20 <= 'f' }
	base := 10
	switch {
	case len(s) > 2 && s[0] == '0' && s[1]|0x20 == 'x' && hex(s[2]):
		base, s = 16, s[2:]
	case s != "" && s[0] == '0':
		base = 8
	}
	end := 0
	for end < len(s) {
		c := s[end]
		d := 99
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case hex(c):
			d = int(c|0x20-'a') + 10
		}
		if d >= base {
			break
		}
		end++
	}
	if end == 0 {
		return nil, unit
	}
	n, _ = new(big.Int).SetString(s[:end], base)
	if neg {
		n.Neg(n)
	}
	// strtoimax and strtoumax saturate with ERANGE before any unit is read.
	if n.Cmp(big.NewInt(math.MinInt64)) < 0 || n.Cmp(new(big.Int).SetUint64(math.MaxUint64)) > 0 || min.Sign() < 0 && n.Cmp(big.NewInt(math.MaxInt64)) > 0 {
		return nil, rng
	}
	factor := int64(0)
	switch strings.ToLower(s[end:]) {
	case "":
		factor = 1
	case "k":
		factor = 1 << 10
	case "m":
		factor = 1 << 20
	case "g":
		factor = 1 << 30
	default:
		return nil, unit
	}
	n.Mul(n, big.NewInt(factor))
	if n.Cmp(min) < 0 || n.Cmp(max) > 0 {
		return nil, rng
	}
	return n, ""
}
