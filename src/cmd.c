// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * strscpy() function definition, to be used instead of strcpy.
 * For more information, see:
 * https://github.com/KSPP/linux/issues/88
 * https://stackoverflow.com/questions/54601208/what-defines-strscpy-in-c
 */
size_t strscpy(char dest[restrict /*size*/],
				  const char src[restrict /*size*/],
				  size_t size)
{
	size_t len;

	if (size <= 0)
		return -E2BIG;

	len = strnlen(src, size - 1);
	memcpy(dest, src, len);
	dest[len] = '\0';

	return len;
}

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	if (!dir || !dir->string)
		return false;

	if (chdir(dir->string) == -1)
		return false;

	return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	exit(EXIT_SUCCESS);
	return SHELL_EXIT;
}

/**
 * Redirections
 */
static void redirect(simple_command_t *s, int cmd_cd, char *cwd)
{
	// <
	if (s->in) {
		int fd = -1;
		char path[PATH_MAX];

		// Execute cd where it was called
		if (cmd_cd)
			snprintf(path, sizeof(path), "%s/%s", cwd, s->in->string);
		else
			strscpy(path, s->in->string, sizeof(path));

		// Add environment variables to path
		if (s->in->next_part)
			strcat(path, get_word(s->in->next_part));

		fd = open(path, O_RDONLY);

		DIE(fd == -1, "open stdin");
		dup2(fd, STDIN_FILENO);
		close(fd);
	}

	// &>
	if (s->out && s->err) {
		char out_path[PATH_MAX];
		char err_path[PATH_MAX];

		// Execute cd where it was called
		if (cmd_cd) {
			snprintf(out_path, sizeof(out_path), "%s/%s", cwd, s->out->string);
			snprintf(err_path, sizeof(err_path), "%s/%s", cwd, s->err->string);
		} else {
			strscpy(out_path, s->out->string, sizeof(out_path));
			strscpy(err_path, s->err->string, sizeof(err_path));
		}

		// Add environment variables to path
		if (s->out->next_part)
			strcat(out_path, get_word(s->out->next_part));
		if (s->err->next_part)
			strcat(err_path, get_word(s->err->next_part));

		int fd_out = open(out_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
		int fd_err = open(err_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

		DIE(fd_out == -1, "open stdout");
		DIE(fd_err == -1, "open stderr");

		dup2(fd_out, STDOUT_FILENO);
		dup2(fd_err, STDERR_FILENO);

		close(fd_out);
		close(fd_err);
	} else {
		// >, >>
		if (s->out) {
			int fd = -1;
			char path[PATH_MAX];

			// Execute cd where it was called
			if (cmd_cd)
				snprintf(path, sizeof(path), "%s/%s", cwd, s->out->string);
			else
				strscpy(path, s->out->string, sizeof(path));

			// Add environment variables to path
			if (s->out->next_part)
				strcat(path, get_word(s->out->next_part));

			if (s->io_flags == IO_REGULAR) {
				// Don't append
				fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			} else if (s->io_flags == IO_OUT_APPEND) {
				// Append
				fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
			}

			DIE(fd == -1, "open stdout");
			dup2(fd, STDOUT_FILENO);
			close(fd);
		}

		// 2>, 2>>
		if (s->err) {
			int fd = -1;
			char path[PATH_MAX];

			// Execute cd where it was called
			if (cmd_cd)
				snprintf(path, sizeof(path), "%s/%s", cwd, s->err->string);
			else
				strscpy(path, s->err->string, sizeof(path));

			// Add environment variables to path
			if (s->err->next_part)
				strcat(path, get_word(s->err->next_part));

			if (s->io_flags == IO_REGULAR) {
				// Don't append
				fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			} else if (s->io_flags == IO_ERR_APPEND) {
				// Append
				fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
			}

			DIE(fd == -1, "open stderr");
			dup2(fd, STDERR_FILENO);
			close(fd);
		}
	}
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	bool cmd_cd = false;
	char cwd[1024];

	int exit_status = 0;

	/* Sanity checks. */
	if (!s || getcwd(cwd, sizeof(cwd)) == NULL)
		return 0;

	/* If builtin command, execute the command. */
	if (strcmp(s->verb->string, "cd") == 0) {
		// Check number of parameters
		if (s->params == NULL || s->params->next_part != NULL)
			return 0;

		cmd_cd = true;

		int stdin_fd = dup(STDIN_FILENO);
		int stdout_fd = dup(STDOUT_FILENO);
		int stderr_fd = dup(STDERR_FILENO);

		redirect(s, cmd_cd, cwd);

		dup2(stdin_fd, STDIN_FILENO);
		dup2(stdout_fd, STDOUT_FILENO);
		dup2(stderr_fd, STDERR_FILENO);

		close(stdin_fd);
		close(stdout_fd);
		close(stderr_fd);

		return shell_cd(s->params);
	}

	if (strcmp(s->verb->string, "exit") == 0 || strcmp(s->verb->string, "quit") == 0)
		return shell_exit();

	if (strcmp(s->verb->string, "false") == 0)
		return false;

	if (strcmp(s->verb->string, "true") == 0)
		return true;

	/* If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	if (s->verb->next_part) {
		char *value = get_word(s->verb->next_part->next_part);

		setenv(s->verb->string, value, 1);

		free(value);
		return 1;
	}

	/* If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */
	pid_t pid = fork();

	if (pid == -1) {
		return 0;
	} else if (pid == 0) {
		// Child process
		int stdin_fd = dup(STDIN_FILENO);
		int stdout_fd = dup(STDOUT_FILENO);
		int stderr_fd = dup(STDERR_FILENO);

		int argc;
		char **argv = get_argv(s, &argc);

		redirect(s, cmd_cd, cwd);

		if (execvp(argv[0], argv) < 0) {
			fprintf(stderr, "Execution failed for '%s'\n", s->verb->string);
			exit(1);
		}

		for (int i = 0; i < argc; i++)
			free(argv[i]);
		free(argv);

		dup2(stdin_fd, STDIN_FILENO);
		dup2(stdout_fd, STDOUT_FILENO);
		dup2(stderr_fd, STDERR_FILENO);

		close(stdin_fd);
		close(stdout_fd);
		close(stderr_fd);
	} else {
		int status;

		waitpid(pid, &status, 0);

		if (WEXITSTATUS(status))
			return 0;
		else
			return 1;
	}

	return exit_status;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* Execute cmd1 and cmd2 simultaneously. */
	pid_t pid1, pid2;
	int status1, status2;

	pid1 = fork();
	if (pid1 < 0) {
		return false;
	} else if (pid1 == 0) {
		// Process child 1
		int exit_status = parse_command(cmd1, level + 1, father);

		exit(exit_status);
	}

	pid2 = fork();
	if (pid2 < 0) {
		return false;
	} else if (pid2 == 0) {
		// Process child 2
		int exit_status = parse_command(cmd2, level + 1, father);

		exit(exit_status);
	}

	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	if (WEXITSTATUS(status1) == 0 && WEXITSTATUS(status2) == 0)
		return true;

	return false;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* Redirect the output of cmd1 to the input of cmd2. */
	int stdin_fd = dup(STDIN_FILENO);
	int stdout_fd = dup(STDOUT_FILENO);
	int stderr_fd = dup(STDERR_FILENO);

	// Read, Write
	int fd[2];

	pid_t pid1, pid2;
	int status1, status2;

	int res = pipe(fd);

	DIE(res == -1, "pipe");

	pid1 = fork();
	if (pid1 < 0) {
		return false;
	} else if (pid1 == 0) {
		// Process child 1
		close(fd[READ]);
		dup2(fd[WRITE], STDOUT_FILENO);
		close(fd[WRITE]);

		int exit_status = parse_command(cmd1, level + 1, father);

		exit(exit_status);
	}

	pid2 = fork();
	if (pid2 < 0) {
		return false;
	} else if (pid2 == 0) {
		// Process child 2
		close(fd[WRITE]);
		dup2(fd[READ], STDIN_FILENO);
		close(fd[READ]);

		int exit_status = parse_command(cmd2, level + 1, father);

		exit(exit_status);
	}

	close(fd[READ]);
	close(fd[WRITE]);
	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	dup2(stdin_fd, STDIN_FILENO);
	dup2(stdout_fd, STDOUT_FILENO);
	dup2(stderr_fd, STDERR_FILENO);

	close(stdin_fd);
	close(stdout_fd);
	close(stderr_fd);

	return WEXITSTATUS(status2);
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* sanity checks */
	if (!c)
		return 0;

	int exit_code = 1;

	if (c->op == OP_NONE) {
		/* Execute a simple command. */
		return parse_simple(c->scmd, level + 1, c);
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* Execute the commands one after the other. */
		parse_command(c->cmd1, level, c);
		parse_command(c->cmd2, level, c);
		break;

	case OP_PARALLEL:
		/* Execute the commands simultaneously. */
		exit_code = run_in_parallel(c->cmd1, c->cmd2, level, c);
		break;

	case OP_CONDITIONAL_NZERO:
		/* Execute the second command only if the first one
		 * returns non zero.
		 */
		exit_code = parse_command(c->cmd1, level, c);

		if (exit_code == false)
			exit_code = parse_command(c->cmd2, level, c);
		break;

	case OP_CONDITIONAL_ZERO:
		/* Execute the second command only if the first one
		 * returns zero.
		 */
		exit_code = parse_command(c->cmd1, level, c);

		if (exit_code == true)
			exit_code = parse_command(c->cmd2, level, c);
		break;

	case OP_PIPE:
		/* Redirect the output of the first command to the
		 * input of the second.
		 */
		exit_code = run_on_pipe(c->cmd1, c->cmd2, level, c);
		break;

	default:
		return SHELL_EXIT;
	}

	return exit_code;
}
