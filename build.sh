#!/bin/sh

echo "You need to have m4, automake, autoconf, libtool...";
echo "Set AUTO_INSTALL_DEPS=1 to auto-install flex/libfl deps for DEB/RPM systems.";

install_lex_deps() {
	if command -v apt-get >/dev/null 2>&1; then
		apt-get -y update && apt-get -y install flex libfl-dev
		return $?
	fi

	if command -v dnf >/dev/null 2>&1; then
		dnf -y install flex flex-devel
		return $?
	fi

	if command -v yum >/dev/null 2>&1; then
		yum -y install flex flex-devel
		return $?
	fi

	echo "No supported package manager found for auto-install (supported: apt-get, dnf, yum)."
	return 1
}

if [ "x$AUTO_INSTALL_DEPS" = "x1" ] || [ "x$AUTO_INSTALL_DEPS" = "xyes" ]; then
	echo "Attempting to auto-install flex/libfl development dependencies..."
	if ! install_lex_deps; then
		echo "Auto-install failed. Please install manually:"
		echo "  Debian/Ubuntu: apt-get install flex libfl-dev"
		echo "  RHEL/Fedora:   dnf install flex flex-devel"
		exit 1
	fi
fi
#aclocal

list_of_config_files="./src/modules";
#
list_of_config_files_pro="./src/modules_pro";

#echo adding modules
#for file in $list_of_config_files; do
#     echo "AC_CONFIG_FILES([${list_of_config_files}/${file}])"
#done  > modules_makefiles.m4

autoreconf --force --install
automake --add-missing
autoconf

CONFIGURE_ARGS=${CONFIGURE_ARGS:---enable-ipv6}
echo "Running ./configure ${CONFIGURE_ARGS}"
./configure ${CONFIGURE_ARGS}
