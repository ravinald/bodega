package main

import "github.com/spf13/cobra"

// A command is classified by whether its success has to reach a running
// bodega serve. The root's PersistentPostRun sends the signal for every
// command that resolves to reloadSignal, so a verb states the fact once where
// it is registered rather than remembering a notifyServer call on each return
// path in its RunE. Four verbs (hide, freeze, refresh and remove) shipped
// without that call, and a withdrawn package stayed published until someone
// restarted the server.
//
// The classification is inherited, so a group carries its whole subtree and a
// leaf overrides its parent. Nothing defaults: TestEveryRunnableCommandIsClassified
// fails the build when a new verb joins the tree undeclared.
const (
	reloadAnnotation = "bodega.reload"
	reloadSignal     = "signal"
	reloadQuiet      = "quiet"
)

// signalsReload marks a verb whose success changes what the server should be
// serving.
func signalsReload(cmd *cobra.Command) *cobra.Command {
	return classifyReload(cmd, reloadSignal)
}

// noReloadSignal marks a verb that needs no signal, either because nothing the
// server holds changed or because the change reaches it another way: the CIDR
// access lists have their own 30s cache, and the apt signing key is published
// as a `systemctl reload` runbook.
func noReloadSignal(cmd *cobra.Command) *cobra.Command {
	return classifyReload(cmd, reloadQuiet)
}

// suppressReload records that this invocation changed nothing, so a verb
// classified as signaling stays quiet for this run. A dry run and a refresh
// that discovered no versions use it.
//
// It fails in the cheap direction: forgetting it costs one redundant reload,
// where forgetting to signal costs an index that keeps publishing a package
// somebody withdrew.
func suppressReload(cmd *cobra.Command) {
	classifyReload(cmd, reloadQuiet)
}

func classifyReload(cmd *cobra.Command, intent string) *cobra.Command {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[reloadAnnotation] = intent
	return cmd
}

// reloadIntent resolves cmd's classification, walking up to its ancestors.
// The second return is false when no command on the path declared one.
func reloadIntent(cmd *cobra.Command) (string, bool) {
	for c := cmd; c != nil; c = c.Parent() {
		if intent, ok := c.Annotations[reloadAnnotation]; ok {
			return intent, true
		}
	}
	return "", false
}
