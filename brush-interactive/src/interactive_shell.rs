use std::io::IsTerminal as _;
use std::io::Write as _;
// MARSH: `Pin` for the boxed future in `LineExecutor::execute`.
use std::pin::Pin;

use crate::InputBackend;
use crate::InteractivePrompt;
use crate::ReadResult;
use crate::ShellError;

/// Result of an interactive execution.
pub enum InteractiveExecutionResult {
    /// The command was executed and returned the given result.
    Executed(brush_core::ExecutionResult),
    /// The command failed to execute.
    Failed(brush_core::Error),
    /// End of input was reached.
    Eof,
}

impl From<&InteractiveExecutionResult> for i32 {
    /// Converts an `InteractiveExecutionResult` into a signed, 32-bit exit code.
    fn from(value: &InteractiveExecutionResult) -> Self {
        match value {
            InteractiveExecutionResult::Executed(result) => u8::from(result.exit_code).into(),
            InteractiveExecutionResult::Failed(_) => 1,
            InteractiveExecutionResult::Eof => 0,
        }
    }
}

/// Options for interactive shells.
#[derive(Clone)]
pub struct InteractiveOptions {
    /// Whether terminal shell integration is enabled.
    pub terminal_shell_integration: bool,
    /// Whether or not to run `PROMPT_COMMAND` before each prompt.
    pub run_prompt_command: bool,
    /// Whether or not to run zsh-style exec/cmd functions (e.g., `preexec_functions`,
    /// `precmd_functions`).
    pub run_cmd_exec_funcs: bool,
}

impl Default for InteractiveOptions {
    fn default() -> Self {
        Self {
            terminal_shell_integration: false,
            run_prompt_command: true,
            run_cmd_exec_funcs: false,
        }
    }
}

// MARSH: a front-end may take over execution of every submitted line and observe prompt turns.
/// A front-end that executes submitted lines on behalf of an [`InteractiveShell`].
///
/// Upstream `execute_line` calls `shell.run_string(...)`, i.e. every line runs *in this process*.
/// `marsh` needs each line to become one `ShellMux` transaction — a btrfs snapshot plus a traced
/// child attached to the real terminal — while keeping this crate's line editing, history,
/// completion and prompt composition. There is no upstream hook for that, so execution is made
/// injectable here.
pub trait LineExecutor<SE: brush_core::ShellExtensions>: Send {
    /// Executes one submitted line, returning the result the interactive loop should observe.
    ///
    /// The shell is *not* locked when this is called, so an implementation may lock it itself.
    /// Returning [`InteractiveExecutionResult::Executed`] with a result whose
    /// `next_control_flow` is `ExitShell` ends the loop, exactly as the `exit` builtin does.
    ///
    /// # Arguments
    ///
    /// * `shell` - The shell the line was submitted to.
    /// * `line` - The submitted line, verbatim.
    fn execute<'a>(
        &'a mut self,
        shell: &'a crate::ShellRef<SE>,
        line: String,
    ) -> Pin<Box<dyn Future<Output = Result<InteractiveExecutionResult, ShellError>> + Send + 'a>>;

    /// Called once per loop turn, before the prompt is composed.
    ///
    /// This is where a front-end reaps its own background work, so that whatever it prints lands
    /// above the next prompt rather than in the middle of the line the user is editing.
    fn before_prompt(&mut self);

    // MARSH: a line editor in raw mode receives Ctrl-C as a keystroke, so the process never sees
    // SIGINT and this is the only place a front-end can observe an interrupt at the prompt.
    /// Observes a prompt-level interrupt, optionally deciding the loop's outcome.
    ///
    /// `None` keeps the default: the interrupt sets the shell's exit status and a fresh prompt is
    /// drawn. `Some` is returned to the loop as this turn's result, so a front-end may end the
    /// session.
    fn on_interrupt(&mut self) -> Option<InteractiveExecutionResult> {
        None
    }

    // MARSH: the loop breaks on end of input without asking anyone; a front-end that has teardown
    // of its own — jobs holding open transactions — needs to see it first.
    /// Observes end of input, optionally deciding the loop's outcome.
    ///
    /// `None` keeps the default: the loop ends. `Some` is returned to the loop as this turn's
    /// result, so a front-end may keep the session open.
    fn on_eof(&mut self) -> Option<InteractiveExecutionResult> {
        None
    }
}

/// Represents an interactive shell that displays prompts, interactively reads user input, etc.
pub struct InteractiveShell<'a, IB: InputBackend, SE: brush_core::ShellExtensions> {
    /// The underlying shell instance.
    shell: crate::ShellRef<SE>,
    /// The input backend to use.
    input: &'a mut IB,
    /// Terminal integration utility, if any.
    terminal_integration: Option<crate::term_integration::TerminalIntegration>,
    /// Terminal-control guard, held for the lifetime of the interactive shell.
    _terminal_control: Option<brush_core::terminal::TerminalControl>,
    /// Options.
    options: InteractiveOptions,
    // MARSH: installed front-end executor; `None` keeps upstream in-process execution.
    /// Front-end that executes submitted lines instead of this shell, if one is installed.
    line_executor: Option<Box<dyn LineExecutor<SE>>>,
}

impl<'a, IB: InputBackend, SE: brush_core::ShellExtensions> InteractiveShell<'a, IB, SE> {
    /// Creates a new `InteractiveShell` wrapping the given shell instance.
    ///
    /// # Arguments
    ///
    /// * `shell` - The shell instance to wrap.
    /// * `input` - The input backend to use.
    /// * `options` - The user interface options to use.
    pub fn new(
        shell: &crate::ShellRef<SE>,
        input: &'a mut IB,
        options: &InteractiveOptions,
    ) -> Result<Self, ShellError> {
        let stdin_is_terminal = std::io::stdin().is_terminal();

        // Acquire terminal control if stdin is a terminal.
        let terminal_control = if stdin_is_terminal {
            Some(brush_core::terminal::TerminalControl::acquire()?)
        } else {
            None
        };

        // Set up terminal integration if enabled *and* if stdin is a terminal.
        let terminal_integration = if options.terminal_shell_integration && stdin_is_terminal {
            let terminfo = crate::term_detection::get_terminal_info(&HostEnvironment);
            let terminal_integration = crate::term_integration::TerminalIntegration::new(terminfo);

            print!("{}", terminal_integration.initialize().as_ref());
            std::io::stdout().flush()?;

            Some(terminal_integration)
        } else {
            None
        };

        Ok(Self {
            shell: shell.clone(),
            input,
            terminal_integration,
            _terminal_control: terminal_control,
            options: options.clone(),
            // MARSH: no executor until one is installed by `set_line_executor`.
            line_executor: None,
        })
    }

    // MARSH: installation point for the front-end executor.
    /// Installs a [`LineExecutor`], which takes over execution of every submitted line.
    ///
    /// # Arguments
    ///
    /// * `executor` - The executor to install.
    pub fn set_line_executor(&mut self, executor: Box<dyn LineExecutor<SE>>) {
        self.line_executor = Some(executor);
    }

    /// Runs the interactive shell loop, reading commands from standard input and writing
    /// results to standard output and standard error. Continues until the shell
    /// normally exits or until a fatal error occurs.
    pub async fn run_interactively(&mut self) -> Result<(), ShellError> {
        let mut shell = self.shell.lock().await;

        let mut announce_exit = shell.options().interactive;

        shell.start_interactive_session()?;

        drop(shell);

        loop {
            let result = self.run_interactively_once().await?;
            match result {
                InteractiveExecutionResult::Executed(brush_core::ExecutionResult {
                    next_control_flow: brush_core::results::ExecutionControlFlow::ExitShell,
                    ..
                }) => {
                    break;
                }
                InteractiveExecutionResult::Executed(brush_core::ExecutionResult {
                    next_control_flow:
                        brush_core::results::ExecutionControlFlow::ReturnFromFunctionOrScript,
                    ..
                }) => {
                    tracing::error!("return from non-function/script");
                }
                InteractiveExecutionResult::Executed(_) => {}
                InteractiveExecutionResult::Failed(err) => {
                    // Report the error, but continue to execute.
                    let shell = self.shell.lock().await;
                    let mut stderr = shell.stderr();
                    let _ = shell.display_error(&mut stderr, &err);

                    drop(shell);
                }
                InteractiveExecutionResult::Eof => {
                    break;
                }
            }

            if self.shell.lock().await.options().exit_after_one_command {
                announce_exit = false;
                break;
            }
        }

        let mut shell = self.shell.lock().await;

        shell.end_interactive_session()?;

        if announce_exit {
            writeln!(shell.stderr(), "exit")?;
        }

        if let Err(e) = shell.save_history() {
            // N.B. This seems like the sort of thing that's worth being noisy about,
            // but bash doesn't do that -- and probably for a reason.
            tracing::debug!("couldn't save history: {e}");
        }

        // Give the shell an opportunity to perform any on-exit operations.
        shell.on_exit().await?;

        drop(shell);

        Ok(())
    }

    /// Runs the interactive shell loop once, reading a single command from standard input.
    async fn run_interactively_once(&mut self) -> Result<InteractiveExecutionResult, ShellError> {
        // MARSH: the installed executor's once-per-turn callback, before anything composes a
        // prompt: a front-end reaps its finished background work here, so its reports land above
        // the next prompt instead of over the line the user is editing.
        if let Some(executor) = self.line_executor.as_mut() {
            executor.before_prompt();
        }

        let mut shell = self.shell.lock().await;

        // Run any pre-prompt actions.
        Self::run_pre_prompt_actions(&mut shell, &self.options).await?;

        // Compose the prompt.
        let prompt = Self::compose_prompt(&mut shell, self.terminal_integration.as_ref()).await?;

        drop(shell);

        // Read input.
        match self.input.read_line(&self.shell, prompt)? {
            ReadResult::Input(read_result) => {
                // We got a line of input -- execute it.
                self.execute_line(read_result, true /* user input */).await
            }
            ReadResult::BoundCommand(read_result) => {
                // We got a line that was bound to keybindings; execute it.
                self.execute_line(read_result, false /* user input */).await
            }
            ReadResult::Eof => {
                // MARSH: a front-end may decline the end of input — to warn about running jobs, for
                // instance — before the loop breaks.
                if let Some(executor) = self.line_executor.as_mut()
                    && let Some(result) = executor.on_eof()
                {
                    return Ok(result);
                }
                // We're done!
                Ok(InteractiveExecutionResult::Eof)
            }
            ReadResult::Interrupted => {
                // MARSH: a front-end may turn an interrupt into its own outcome — ending the
                // session, for instance — before the default "note it and reprompt".
                if let Some(executor) = self.line_executor.as_mut()
                    && let Some(result) = executor.on_interrupt()
                {
                    return Ok(result);
                }
                // We were interrupted; report that appropriately.
                let result: brush_core::ExecutionResult =
                    brush_core::ExecutionExitCode::Interrupted.into();
                self.shell
                    .lock()
                    .await
                    .set_last_exit_status(result.exit_code.into());
                Ok(InteractiveExecutionResult::Executed(result))
            }
        }
    }

    async fn compose_prompt(
        shell: &mut brush_core::Shell<SE>,
        terminal_integration: Option<&crate::term_integration::TerminalIntegration>,
    ) -> Result<InteractivePrompt, ShellError> {
        // Now that we've done that, compose the prompt.
        let mut prompt = InteractivePrompt {
            prompt: shell.compose_prompt().await?,
            alt_side_prompt: shell.compose_alt_side_prompt().await?,
            continuation_prompt: shell.compose_continuation_prompt().await?,
        };

        if let Some(terminal_integration) = terminal_integration {
            let pre_prompt = terminal_integration.pre_prompt();
            let working_dir = terminal_integration.report_cwd(shell.working_dir());
            let post_prompt = terminal_integration.post_prompt();

            prompt.prompt = [
                pre_prompt.as_ref(),
                working_dir.as_ref(),
                prompt.prompt.as_str(),
                post_prompt.as_ref(),
            ]
            .concat();
        }

        Ok(prompt)
    }

    /// Executes the given line of input.
    ///
    /// # Arguments
    ///
    /// * `read_result` - The line of input to execute.
    /// * `user_input` - Whether the line came from direct user input (as opposed to a key binding,
    ///   say).
    async fn execute_line(
        &mut self,
        read_result: String,
        user_input: bool,
    ) -> Result<InteractiveExecutionResult, ShellError> {
        let mut shell = self.shell.lock().await;

        // See if the the user interface has a non-empty read buffer.
        let buffer_info = self.input.get_read_buffer();

        // If the user interface has a read buffer -- even an empty one -- reflect it to the
        // shell so that bound commands see READLINE_LINE/READLINE_POINT, as they do in bash.
        let had_buffer = if let Some((buffer, cursor)) = buffer_info {
            shell.set_edit_buffer(buffer, cursor)?;
            true
        } else {
            false
        };

        // If the line came from direct user input (as opposed to a key binding, say), then we
        // need to do a few more things before executing it.
        if user_input {
            Self::run_pre_exec_actions(
                &mut shell,
                read_result.as_str(),
                &self.options,
                self.terminal_integration.as_ref(),
            )
            .await?;
        }

        // Count the command's lines.
        let line_count = read_result.lines().count().max(1);

        // MARSH: hand the line to the installed executor, if any. This sits *after*
        // `run_pre_exec_actions` so `shell.add_to_history` still records every submitted line, and
        // the shell lock is released first because the executor is given the `ShellRef` and may
        // lock it itself. With no executor installed, the line runs in this process as upstream.
        let result = if let Some(executor) = self.line_executor.as_mut() {
            drop(shell);
            let result = executor.execute(&self.shell, read_result).await;
            shell = self.shell.lock().await;
            result
        } else {
            // Execute the command.
            let params = shell.default_exec_params();
            let source_info = brush_core::SourceInfo::from("main");
            match shell.run_string(read_result, &source_info, &params).await {
                Ok(result) => Ok(InteractiveExecutionResult::Executed(result)),
                Err(e) => Ok(InteractiveExecutionResult::Failed(e)),
            }
        };

        // Update cumulative line counter based on actual lines in the command.
        shell.increment_interactive_line_offset(line_count);

        // See if the shell has input buffer state that we need to reflect back to
        // the user interface. It may be state that originally came from the user
        // interface, or it may be state that was programmatically generated by
        // the command we just executed.
        let mut buffer_and_cursor = shell.pop_edit_buffer()?;

        drop(shell);

        if buffer_and_cursor.is_none() && had_buffer {
            buffer_and_cursor = Some((String::new(), 0));
        }

        if let Some((updated_buffer, updated_cursor)) = buffer_and_cursor {
            self.input.set_read_buffer(updated_buffer, updated_cursor);
        }

        // Invoke terminal integration.
        if let Some(terminal_integration) = &self.terminal_integration {
            let exit_code = result.as_ref().map_or(1, i32::from);
            print!(
                "{}",
                terminal_integration.post_exec_command(exit_code).as_ref()
            );
            std::io::stdout().flush()?;
        }

        result
    }

    async fn run_pre_prompt_actions(
        shell: &mut brush_core::Shell<SE>,
        options: &InteractiveOptions,
    ) -> Result<(), ShellError> {
        // Check for any completed jobs.
        shell.check_for_completed_jobs()?;

        // If there's a variable called PROMPT_COMMAND, then run it first.
        if options.run_prompt_command {
            if let Some(prompt_cmd_var) = shell.env_var("PROMPT_COMMAND") {
                match prompt_cmd_var.value() {
                    brush_core::ShellValue::String(cmd_str) => {
                        Self::run_pre_prompt_command(shell, cmd_str.to_owned()).await?;
                    }
                    brush_core::ShellValue::IndexedArray(values) => {
                        let owned_values: Vec<_> = values.values().cloned().collect();
                        for cmd_str in owned_values {
                            Self::run_pre_prompt_command(shell, cmd_str).await?;
                        }
                    }
                    // Other types are ignored.
                    _ => (),
                }
            }
        }

        // Next, run any zsh-style `precmd_functions`.
        // TODO(precmd_functions): verify if we need to save/restore exit results.
        if options.run_cmd_exec_funcs {
            // If there's a variable called precmd_functions, then call them.
            if let Some(brush_core::ShellValue::IndexedArray(precmd_funcs)) = shell
                .env_var("precmd_functions")
                .map(|var| var.value())
                .cloned()
            {
                for func_name in precmd_funcs.values() {
                    let _ = shell
                        .invoke_function(
                            func_name,
                            std::iter::empty::<&str>(),
                            shell.default_exec_params(),
                        )
                        .await;
                }
            }
        }

        Ok(())
    }

    async fn run_pre_exec_actions(
        shell: &mut brush_core::Shell<SE>,
        command_line: &str,
        options: &InteractiveOptions,
        terminal_integration: Option<&crate::term_integration::TerminalIntegration>,
    ) -> Result<(), ShellError> {
        // Display the pre-command prompt on stderr (if there is one).
        let precmd_prompt = shell.compose_precmd_prompt().await?;
        if !precmd_prompt.is_empty() {
            eprint!("{precmd_prompt}");
            std::io::stderr().flush()?;
        }

        // Update history (if applicable).
        shell.add_to_history(command_line.trim_end_matches('\n'))?;

        // Next, run any zsh-style `preexec_functions`.
        // TODO(preexec_functions): verify if we need to save/restore exit results.
        if options.run_cmd_exec_funcs {
            // If there's a variable called preexec_functions, then call them.
            if let Some(brush_core::ShellValue::IndexedArray(preexec_funcs)) = shell
                .env_var("preexec_functions")
                .map(|var| var.value())
                .cloned()
            {
                for func_name in preexec_funcs.values() {
                    let _ = shell
                        .invoke_function(func_name, &[command_line], shell.default_exec_params())
                        .await;
                }
            }
        }

        // Invoke terminal integration.
        if let Some(terminal_integration) = terminal_integration {
            print!(
                "{}",
                terminal_integration.pre_exec_command(command_line).as_ref()
            );
            std::io::stdout().flush()?;
        }

        Ok(())
    }

    async fn run_pre_prompt_command(
        shell: &mut brush_core::Shell<SE>,
        prompt_cmd: String,
    ) -> Result<(), ShellError> {
        // Save (and later restore) the last exit status.
        let prev_last_result = shell.last_exit_status();
        let prev_last_pipeline_statuses = shell.last_pipeline_statuses().to_vec();

        // Run the command.
        let params = shell.default_exec_params();
        let source_info = brush_core::SourceInfo::from("PROMPT_COMMAND");
        shell.run_string(prompt_cmd, &source_info, &params).await?;

        // Restore the last exit status.
        *shell.last_pipeline_statuses_mut() = prev_last_pipeline_statuses;
        shell.set_last_exit_status(prev_last_result);

        Ok(())
    }
}

/// Represents the host environment; used for terminal detection in conjunction
/// with the `TerminalEnvironment` trait.
struct HostEnvironment;

impl crate::term_detection::TerminalEnvironment for HostEnvironment {
    /// Gets the value of the given environment variable from the host process's
    /// OS environment variables. Returns `None` if the variable is not set.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the environment variable to get.
    fn get_env_var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}
