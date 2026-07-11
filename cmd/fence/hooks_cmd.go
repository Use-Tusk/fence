package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/fencesandbox/fence/internal/importer"
	"github.com/spf13/cobra"
)

func newHooksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hooks",
		Short: "Print and manage editor/agent hook integrations",
	}

	cmd.AddCommand(newHooksPrintCmd())
	cmd.AddCommand(newHooksInstallCmd())
	cmd.AddCommand(newHooksUninstallCmd())
	return cmd
}

func newHooksPrintCmd() *cobra.Command {
	var (
		claude      bool
		codex       bool
		cursor      bool
		opencode    bool
		hermes      bool
		windsurf    bool
		hookOptions hookFenceOptions
	)

	cmd := &cobra.Command{
		Use:   "print",
		Short: "Print hook config for supported integrations",
		Long: `Print hook configuration snippets for supported integrations.

Examples:
  fence hooks print --claude
  fence hooks print --claude --settings ./fence.json
  fence hooks print --codex
  fence hooks print --codex --template code
  fence hooks print --codex --wrap
  fence hooks print --cursor --template code
  fence hooks print --opencode
  fence hooks print --hermes
  fence hooks print --windsurf`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedHookOptions, err := hookOptions.normalized()
			if err != nil {
				return fmt.Errorf("failed to resolve hook policy options: %w", err)
			}
			if err := requireCodexOnlyWrap(codex, resolvedHookOptions); err != nil {
				return err
			}

			switch {
			case claude:
				return writeClaudeHooksConfigWithOptions(cmd.OutOrStdout(), resolvedHookOptions)
			case codex:
				return writeCodexHooksConfigWithOptions(cmd.OutOrStdout(), resolvedHookOptions)
			case cursor:
				return writeCursorHooksConfigWithOptions(cmd.OutOrStdout(), resolvedHookOptions)
			case opencode:
				if resolvedHookOptions.SettingsPath != "" || resolvedHookOptions.TemplateName != "" {
					return fmt.Errorf("--settings/--template are not supported with --opencode (OpenCode plugins do not accept options through the plugin array; use a local plugin shim instead, see https://github.com/fencesandbox/opencode-fence)")
				}
				return writeOpencodeHooksConfig(cmd.OutOrStdout())
			case hermes:
				return writeHermesHooksConfig(cmd.OutOrStdout(), resolvedHookOptions)
			case windsurf:
				return writeWindsurfHooksConfigWithOptions(cmd.OutOrStdout(), resolvedHookOptions)
			default:
				return fmt.Errorf("no hook target specified. Use --claude, --codex, --cursor, --opencode, --hermes, or --windsurf")
			}
		},
	}

	cmd.Flags().BoolVar(&claude, "claude", false, "Print Claude Code hook config")
	cmd.Flags().BoolVar(&codex, "codex", false, "Print Codex / ChatGPT Codex hook config")
	cmd.Flags().BoolVar(&cursor, "cursor", false, "Print Cursor hook config")
	cmd.Flags().BoolVar(&opencode, "opencode", false, "Print OpenCode plugin config")
	cmd.Flags().BoolVar(&hermes, "hermes", false, "Print Hermes shell-hook config (~/.hermes/config.yaml)")
	cmd.Flags().BoolVar(&windsurf, "windsurf", false, "Print Windsurf Cascade hook config")
	addHookPolicyFlags(cmd, &hookOptions)
	cmd.MarkFlagsMutuallyExclusive("claude", "codex", "cursor", "opencode", "hermes", "windsurf")
	return cmd
}

func newHooksInstallCmd() *cobra.Command {
	var (
		claude      bool
		codex       bool
		cursor      bool
		opencode    bool
		hermes      bool
		windsurf    bool
		path        string
		force       bool
		hookOptions hookFenceOptions
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install hook config into supported integrations",
		Long: `Install hook configuration into supported integrations.

Examples:
  fence hooks install --claude
  fence hooks install --claude --file ./.claude/settings.json
  fence hooks install --claude --settings ./fence.json
  fence hooks install --codex
  fence hooks install --codex --template code --file ./.codex/hooks.json
  fence hooks install --codex --wrap
  fence hooks install --cursor --template code --file ./.cursor/hooks.json
  fence hooks install --opencode
  fence hooks install --opencode --file ./opencode.json
  fence hooks install --opencode --force                          # skip prompt
  fence hooks install --hermes
  fence hooks install --hermes --settings ./fence.json
  fence hooks install --hermes --file ./project-hermes-config.yaml
  fence hooks install --windsurf
  fence hooks install --windsurf --file ./.windsurf/hooks.json

` + hooksFileFlagDefaultsHelp,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedHookOptions, err := hookOptions.normalized()
			if err != nil {
				return fmt.Errorf("failed to resolve hook policy options: %w", err)
			}
			if err := requireCodexOnlyWrap(codex, resolvedHookOptions); err != nil {
				return err
			}

			switch {
			case claude:
				targetPath := path
				if targetPath == "" {
					targetPath = importer.DefaultClaudeSettingsPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Claude settings path")
				}
				changed, err := installClaudeHookWithOptions(targetPath, resolvedHookOptions)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Installed Claude hook in %q\n", targetPath); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Claude hook already installed in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			case codex:
				targetPath := path
				if targetPath == "" {
					targetPath = defaultCodexHooksPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Codex hooks path")
				}
				changed, err := installCodexHookWithOptions(targetPath, resolvedHookOptions)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Installed Codex hook in %q\n", targetPath); err != nil {
						return err
					}
					if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "Note: Codex requires reviewing and trusting new hooks via /hooks before they run."); err != nil {
						return err
					}
					if resolvedHookOptions.AllowWrap {
						if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "Note: --wrap rewrites allowed commands to fence -c. Use only when Codex's own sandbox is disabled; otherwise nested Fence cannot bind its proxy."); err != nil {
							return err
						}
					} else {
						if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "Note: Codex hooks are intent-only by default (deny blocked commands). Pass --wrap only if Codex's sandbox is disabled and you want fence -c rewriting."); err != nil {
							return err
						}
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Codex hook already installed in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			case cursor:
				targetPath := path
				if targetPath == "" {
					targetPath = defaultCursorHooksPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Cursor hooks path")
				}
				changed, err := installCursorHookWithOptions(targetPath, resolvedHookOptions)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Installed Cursor hook in %q\n", targetPath); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Cursor hook already installed in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			case opencode:
				if resolvedHookOptions.SettingsPath != "" || resolvedHookOptions.TemplateName != "" {
					return fmt.Errorf("--settings/--template are not supported with --opencode (OpenCode plugins do not accept options through the plugin array; use a local plugin shim instead, see https://github.com/fencesandbox/opencode-fence)")
				}
				targetPath := path
				if targetPath == "" {
					targetPath = resolveOpencodeConfigPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine OpenCode config path")
				}
				if !confirmJSONCCommentLossOrAbort(cmd.InOrStdin(), cmd.ErrOrStderr(), targetPath, force) {
					return nil
				}
				changed, err := installOpencodePlugin(targetPath)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Installed OpenCode plugin in %q\n", targetPath); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "OpenCode plugin already installed in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			case hermes:
				targetPath := path
				if targetPath == "" {
					targetPath = defaultHermesConfigPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Hermes config path")
				}
				changed, err := installHermesHook(targetPath, resolvedHookOptions)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Installed Hermes hooks in %q\n", targetPath); err != nil {
						return err
					}
					if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "Note: Hermes prompts on first use of each hook. For non-TTY runs (gateway, cron) set HERMES_ACCEPT_HOOKS=1 or hooks_auto_accept: true."); err != nil {
						return err
					}
					for _, line := range hermesEmptyPolicyAdvice(resolvedHookOptions) {
						if _, err := fmt.Fprintln(cmd.ErrOrStderr(), line); err != nil {
							return err
						}
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Hermes hooks already installed in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			case windsurf:
				targetPath := path
				if targetPath == "" {
					targetPath = defaultWindsurfHooksPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Windsurf hooks path")
				}
				changed, err := installWindsurfHook(targetPath, resolvedHookOptions)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Installed Windsurf hooks in %q\n", targetPath); err != nil {
						return err
					}
					for _, line := range windsurfEmptyPolicyAdvice(resolvedHookOptions) {
						if _, err := fmt.Fprintln(cmd.ErrOrStderr(), line); err != nil {
							return err
						}
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Windsurf hooks already installed in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			default:
				return fmt.Errorf("no hook target specified. Use --claude, --codex, --cursor, --opencode, --hermes, or --windsurf")
			}
		},
	}

	cmd.Flags().BoolVar(&claude, "claude", false, "Install Claude Code hook config")
	cmd.Flags().BoolVar(&codex, "codex", false, "Install Codex / ChatGPT Codex hook config")
	cmd.Flags().BoolVar(&cursor, "cursor", false, "Install Cursor hook config")
	cmd.Flags().BoolVar(&opencode, "opencode", false, "Install OpenCode plugin config")
	cmd.Flags().BoolVar(&hermes, "hermes", false, "Install Hermes shell-hook config")
	cmd.Flags().BoolVar(&windsurf, "windsurf", false, "Install Windsurf Cascade hook config")
	cmd.Flags().StringVarP(&path, "file", "f", "", "Path to the settings/hooks file to modify")
	cmd.Flags().BoolVarP(&force, "force", "y", false, "Skip the confirmation prompt when comments would be stripped")
	addHookPolicyFlags(cmd, &hookOptions)
	cmd.MarkFlagsMutuallyExclusive("claude", "codex", "cursor", "opencode", "hermes", "windsurf")
	return cmd
}

func newHooksUninstallCmd() *cobra.Command {
	var (
		claude   bool
		codex    bool
		cursor   bool
		opencode bool
		hermes   bool
		windsurf bool
		path     string
		force    bool
	)

	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove hook config from supported integrations",
		Long: `Remove hook configuration from supported integrations.

Examples:
  fence hooks uninstall --claude
  fence hooks uninstall --claude --file ./.claude/settings.json
  fence hooks uninstall --codex
  fence hooks uninstall --codex --file ./.codex/hooks.json
  fence hooks uninstall --cursor --file ./.cursor/hooks.json
  fence hooks uninstall --opencode
  fence hooks uninstall --opencode --force                          # skip prompt
  fence hooks uninstall --hermes
  fence hooks uninstall --windsurf

` + hooksFileFlagDefaultsHelp,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case claude:
				targetPath := path
				if targetPath == "" {
					targetPath = importer.DefaultClaudeSettingsPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Claude settings path")
				}
				changed, err := uninstallClaudeHook(targetPath)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Removed Claude hook from %q\n", targetPath); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Claude hook not present in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			case codex:
				targetPath := path
				if targetPath == "" {
					targetPath = defaultCodexHooksPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Codex hooks path")
				}
				changed, err := uninstallCodexHook(targetPath)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Removed Codex hook from %q\n", targetPath); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Codex hook not present in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			case cursor:
				targetPath := path
				if targetPath == "" {
					targetPath = defaultCursorHooksPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Cursor hooks path")
				}
				changed, err := uninstallCursorHook(targetPath)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Removed Cursor hook from %q\n", targetPath); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Cursor hook not present in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			case opencode:
				targetPath := path
				if targetPath == "" {
					targetPath = resolveOpencodeConfigPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine OpenCode config path")
				}
				if !confirmJSONCCommentLossOrAbort(cmd.InOrStdin(), cmd.ErrOrStderr(), targetPath, force) {
					return nil
				}
				changed, err := uninstallOpencodePlugin(targetPath)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Removed OpenCode plugin from %q\n", targetPath); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "OpenCode plugin not present in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			case hermes:
				targetPath := path
				if targetPath == "" {
					targetPath = defaultHermesConfigPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Hermes config path")
				}
				changed, err := uninstallHermesHook(targetPath)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Removed Hermes hooks from %q\n", targetPath); err != nil {
						return err
					}
					if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "Tip: revoke Hermes' shell-hook consent with `hermes hooks revoke 'fence "+hermesPreToolUseMode+"'`."); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Hermes hooks not present in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			case windsurf:
				targetPath := path
				if targetPath == "" {
					targetPath = defaultWindsurfHooksPath()
				}
				if targetPath == "" {
					return fmt.Errorf("could not determine Windsurf hooks path")
				}
				changed, err := uninstallWindsurfHook(targetPath)
				if err != nil {
					return err
				}
				if changed {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Removed Windsurf hooks from %q\n", targetPath); err != nil {
						return err
					}
				} else {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Windsurf hooks not present in %q\n", targetPath); err != nil {
						return err
					}
				}
				return nil
			default:
				return fmt.Errorf("no hook target specified. Use --claude, --codex, --cursor, --opencode, --hermes, or --windsurf")
			}
		},
	}

	cmd.Flags().BoolVar(&claude, "claude", false, "Remove Claude Code hook config")
	cmd.Flags().BoolVar(&codex, "codex", false, "Remove Codex / ChatGPT Codex hook config")
	cmd.Flags().BoolVar(&cursor, "cursor", false, "Remove Cursor hook config")
	cmd.Flags().BoolVar(&opencode, "opencode", false, "Remove OpenCode plugin config")
	cmd.Flags().BoolVar(&hermes, "hermes", false, "Remove Hermes shell-hook config")
	cmd.Flags().BoolVar(&windsurf, "windsurf", false, "Remove Windsurf Cascade hook config")
	cmd.Flags().StringVarP(&path, "file", "f", "", "Path to the settings/hooks file to modify")
	cmd.Flags().BoolVarP(&force, "force", "y", false, "Skip the confirmation prompt when comments would be stripped")
	cmd.MarkFlagsMutuallyExclusive("claude", "codex", "cursor", "opencode", "hermes", "windsurf")
	return cmd
}

const hooksFileFlagDefaultsHelp = `Default --file paths:
  --claude    ~/.claude/settings.json
  --codex     ~/.codex/hooks.json
  --cursor    ~/.cursor/hooks.json
  --opencode  existing ~/.config/opencode/opencode.{jsonc,json}
  --hermes    ~/.hermes/config.yaml
  --windsurf  ~/.codeium/windsurf/hooks.json`

func addHookPolicyFlags(cmd *cobra.Command, hookOptions *hookFenceOptions) {
	cmd.Flags().StringVar(&hookOptions.SettingsPath, "settings", "", "Pin hook policy checks to this Fence settings file")
	cmd.Flags().StringVar(&hookOptions.TemplateName, "template", "", "Pin hook policy checks to this Fence template")
	cmd.Flags().BoolVar(&hookOptions.AllowWrap, "wrap", false, "For --codex only: rewrite allowed commands to fence -c (requires Codex sandbox disabled)")
	cmd.MarkFlagsMutuallyExclusive("settings", "template")
}

func requireCodexOnlyWrap(codex bool, hookOptions hookFenceOptions) error {
	if hookOptions.AllowWrap && !codex {
		return fmt.Errorf("--wrap is only supported with --codex")
	}
	return nil
}

// confirmJSONCCommentLossOrAbort warns and prompts when the pending OpenCode
// install/uninstall would strip JSONC comments. Returns proceed=true when the
// operation should continue (no comments at risk, byte-edit will preserve
// them, force=true, or user answered yes); proceed=false when the user
// declined. Read errors during the checks are intentionally swallowed — any
// real failure will resurface in the install/uninstall step itself.
func confirmJSONCCommentLossOrAbort(in io.Reader, errOut io.Writer, path string, force bool) (proceed bool) {
	hadComments, err := hookConfigHasJSONCComments(path)
	if err != nil || !hadComments {
		return true
	}
	preserves, err := opencodeWillPreserveComments(path)
	if err == nil && preserves {
		return true
	}

	_, _ = fmt.Fprintf(errOut, "warning: %q contains comments, which will be removed when Fence rewrites the file.\nConsider backing up the file first.\n", path)

	if force {
		return true
	}

	_, _ = fmt.Fprint(errOut, "Continue and strip comments? [y/N] ")
	reader := bufio.NewReader(in)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))
	if response != "y" && response != "yes" {
		_, _ = fmt.Fprintln(errOut, "Aborted.")
		return false
	}
	return true
}
