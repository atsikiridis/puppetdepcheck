use strict;
use warnings;

my $debug = 0;

# State
# Initial: Looking for Puppet execution)
# Scanning: Handling system calls and looking for Puppet messages)
# Decode: Decoding a Puppet message
my $state = 'I';

my $puppet_id = 0;
my $puppet_message = '';

# Global handle for system calls
#
# Indexed by system call name
# Contains hash of operations to be performed:
# produce: produce the specified file
# produce2: produce the specified second file
# consume: consume the specified file
# atpath: the specified path is given relative to a file descriptor
# expunge: remove the specified file
# clone, chdir, open, close: special handling for the specified call
my %handle;

# Per process data
#
# Indexed by expanded unique process id
# Each process contains a hash with the following elements
# cwd: current working directory
# fdpath: a map from file descriptors to paths
my %proc;

# Per puppet rule data
my %rule;
my $current_rule;

# Unique process ids
# For a given recyclable process-id this gives the corresponding
# unique process-id
my @unique_proc_id = map($_ .= ':1', 1..32767);

initialize_syscall_handling();

open(IN, '/vol/puppet/setup.trace') || die;
while (<IN>) {
	if ($state eq 'S' && s/^(\d+)\s*(\w+)//) {
		# Process-id, call name, rest
		handle_syscall($1, $2, $_);
	} elsif ($state eq 'D' && /^ \| .....  (.. .. .. .. .. .. .. ..  .. .. .. .. .. .. .. ..)  ................. \|/) {
		#  | 00000  2b 20 72 6d 20 2d 72 66  20 6b 65 79 73 74 6f 72  + rm -rf  keystor |
		# Decode Puppet message
		# print "Decode [$1]\n";
		my @hex = split(/ +/, $1);
		for my $h (@hex) {
			$puppet_message .= sprintf('%c', hex($h));
		}
	} elsif ($state eq 'D') {
		# Finish decoding puppet message
		# Remove escape codes
		$puppet_message =~ s/\e\[\d+(\;\d+)?m//g;
		print "[$puppet_message]\n";
		$puppet_message = '';
		$state = 'S';	# Scanning
	} elsif ($state eq 'I' && /^(\d+)\s+execve\("\/usr\/bin\/puppet",/) {
		# 7458  execve("/usr/bin/puppet", [...],
		# Record Puppet id
		$puppet_id = $1;
		$state = 'S';
		print "$.: Puppet id = [$puppet_id]\n";
	}
}

sub
handle_syscall
{
	my($proc_id, $call_name, $rest) = @_;

	# Don't handle system calls that return an error
	# e.g. "...) = -1 EEXIST (File exists)"
	return if ($rest =~ m/\) \= \-1 E\w+ \([^)]+\)$/);

	print "[$proc_id] [$call_name] [$rest]\n" if ($debug > 3);
	my $current_proc = $proc{$unique_proc_id[$proc_id]};

	my $path;
	if (my $handle = $handle{$call_name}) {

		# consume0: Example symlinkat("/proc/self/fd/0", 3, "stdin")
		# atpath refers to the second argument
		my $path0;
		($path0) = ($rest =~ s/\(\"([^"]*)\"\, /(/) if ($handle{'consume0'});

		if ($handle{'atpath'}) {
			my ($fd, $at_path) = ($rest =~ s/\((\w+)\, \"([^"])\"//);
			if ($fd eq 'AT_FDCWD' || $path =~ m|^/|) {
				$path = $at_path;
			} else {
				# Path relative to fd
				if (!defined($current_proc{'fdpath'}{$fd})) {
					print STDERR qq{$proc_id $call_name($fd, "$at_path"...): Unknown file descriptor\n};
				} else {
					$path = "$current_proc{'fdpath'}{$fd}))/$at_path";
				}
			}
		} else {
			($path) = ($rest =~ s/\(\"([^"]*)\"//);
		} # atpath

		$path = path_make_absolute($current_proc{'cwd'}, $path);


		if ($handle{'consume'}) {
			$current_rule{'consume'}{$path} = 1;
		} elsif ($handle{'produce'}) {
			$current_rule{'produce'}{$path} = 1;
		} elsif ($handle{'expunge'}) {
			if ($current_rule{'produce'}{$path}) {
				# If we produced the file, then production/consumption is a no-op
				undef $current_rule{'produce'}{$path} = 1;
			} else {
				# Otherwise, we consumed it
				$current_rule{'consume'}{$path} = 1;
			}
		} else {
			print STDERR qq{$proc_id $call_name: Unknown system call\n};
		}

		if ($handle{'consume0'}) {
			$current_rule{'consume'}{path_make_absolute($current_proc{'cwd'}, $path0)} = 1;
		}

		if ($handle{'produce2'}) {
			my ($path2) = ($rest =~ s/\, \"([^"]*)\"//);
			$current_rule{'produce'}{path_make_absolute($current_proc{'cwd'}, $path2)} = 1;
		}
	}

	# More handling for special cases
	if ($call_name eq 'open' || $call_name eq 'openat') {
		# Produce or consume the path; see open-modes.txt
		my ($flags) = ($rest =~ s/\, ([^),]*)//);

		if ($flags =~ m/O_RDONLY/) {
			$current_rule{'consume'}{$path} = 1;
		} elsif ($flags =~ m/O_TRUNC|O_WRONLY/) {
			$current_rule{'produce'}{$path} = 1;
		} elsif ($flags =~ m/O_RDWRD/ && $flags =~ m/O_CREAT/) {
			$current_rule{'produce'}{$path} = 1;
			# $current_rule{'consume'}{$path} = 1; # maybe
		} else {
			# Plain O_RDWR
			$current_rule{'consume'}{$path} = 1;
		}

		if ($flags =~ m/O_RDONLY/) {
			$current_rule{'consume'}{$path} = 1;
		}
		if ($flags =~ m/O_CREAT/) {
			$current_rule{'produce'}{$path} = 1;
		} elsif ($flags !~ m/O_TRUNC/) {
			$current_rule{'consume'}{$path} = 1;
		}

		# Remember fd's path for *at operations
		$current_proc{'fdpath'}{$fd} = $path;

	} elsif ($call_name eq 'close') {
		# Stop remembering the fd for at* operations
		undef $current_proc{'fdpath'}{$fd};

	} elsif ($call_name eq 'vfork') {
		# Increase proc_id ordinal; copy open fds XXX

	} elsif ($call_name eq 'clone') {
		# Increase proc_id ordinal; copy / share open fds XXX

	} elsif ($call_name eq 'chdir') {
		# Set processes directory
		$current_proc{'cwd'} = $path;

	} elsif ($call_name eq 'fchdir') {
		# Set processes directory
		my ($fd) = ($rest =~ s/\((\w+)//);
		if (!defined($current_proc{'fdpath'}{$fd})) {
			print STDERR qq{$proc_id $call_name($fd): Unknown file descriptor\n};
		} else {
			$current_proc{'cwd'} = $current_proc{'fdpath'}{$fd};
		}

	} elsif ($proc_id == $puppet_id && $call_name eq 'write' && $rest =~ m/\([12],/) {
		# Decode a puppet message written to stdout, stderr
		$state = 'D';	# Decoding
		# print "Decoding: $_";

	} elsif ($proc_id == $puppet_id && $call_name eq 'getcwd' && $rest =~ m/\(\"([^"]*)\"[^=]*\=\s*\d/) {
		# ("/root/src/sysadmin/puppet", 200) = 26
		# Puppet's working directory
		$proc{$puppet_id}{'cwd'} = $1;
	}
}



# Set the operations to execute for each system call
sub
initialize_syscall_handling
{
	$handle{'chmod'}	= {'consume' => 1};
	$handle{'chdir'}	= {'chdir' => 1};
	$handle{'chown'}	= {'consume' => 1};
	$handle{'clone'}	= {'clone' => 1};
	$handle{'close'}	= {'close' => 1};
	$handle{'creat'}	= {'produce' => 1};
	$handle{'execve'}	= {'consume' => 1};
	$handle{'fchdir'}	= {'fchdir' => 1};
	$handle{'fchmodat'}	= {'consume' => 1, 'atpath' => 1};
	$handle{'fchownat'}	= {'consume' => 1, 'atpath' => 1};
	$handle{'fsetxattr'}	= {'consume' => 1};
	$handle{'getxattr'}	= {'consume' => 1};
	$handle{'lchown'}	= {'consume' => 1};
	$handle{'lgetxattr'}	= {'consume' => 1};
	$handle{'link'}		= {'consume' => 1, 'produce2'};
	$handle{'lstat'}	= {'consume' => 1};
	$handle{'mkdir'}	= {'produce' => 1};
	$handle{'mknod'}	= {'produce' => 1};
	$handle{'newfstatat'}	= {'consume' => 1, 'atpath' => 1};
	$handle{'open'}		= {'open' => 1};
	$handle{'openat'}	= {'open' => 1, 'atpath' => 1};
	$handle{'readlink'}	= {'consume' => 1};
	$handle{'readlinkat'}	= {'consume' => 1, 'atpath' => 1};
	$handle{'removexattr'}	= {'produce' => 1};
	$handle{'rename'}	= {'expunge' => 1, 'produce2' => 1};
	$handle{'rmdir'}	= {'expunge' => 1};
	$handle{'setxattr'}	= {'consume' => 1};
	$handle{'stat'}		= {'consume' => 1};
	$handle{'statfs'}	= {'consume' => 1};
	$handle{'symlink'}	= {'consume' => 1, 'produce2' => 1};
	$handle{'symlinkat'}	= {'consume0' => 1, 'produce' => 1, 'atpath' => 1};
	$handle{'unlink'}	= {'expunge' => 1};
	$handle{'unlinkat'}	= {'expunge' => 1, 'atpath' => 1};
	$handle{'utime'}	= {'consume' => 1};
	$handle{'utimensat'}	= {'consume' => 1, 'atpath' => 1};
	$handle{'utimes'}	= {'consume' => 1};
	$handle{'vfork'}	= {'vfork' => 1};
}

# TODO
# Handle fcntl O_CLOEXEC
