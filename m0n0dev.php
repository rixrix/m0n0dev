#!/usr/local/bin/php -f
<?php
/*
    m0n0dev.php (http://www.askozia.com/m0n0wall/m0n0dev.php)
    
    Copyright (C) 2007 IKT <http://www.itison-ikt.de> 
    All rights reserved.
    
    Authors:
        Michael Iedema <michael.iedema@askozia.com>.
    
    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:
    
    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
    
    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/


// --[ package versions ]------------------------------------------------------

$php_version = "php-4.4.4";
$radius_version = "radius-1.2.5";
$mini_httpd_version = "mini_httpd-1.19";
$wol_version = "wol-0.7.1";
$ez_ipupdate_version = "ez-ipupdate-3.0.11b8";
$bpalogin_version = "bpalogin-2.0.2";
$ucd_snmp_version = "ucd-snmp-4.2.7";
$mpd_version = "mpd-3.18";
$ipsec_tools_version = "ipsec-tools-0.6.6";


// --[ possible platforms and kernels ]----------------------------------------

$platform_list = "net45xx net48xx wrap generic-pc generic-pc-cdrom";
$platforms = explode(" ", $platform_list);


// --[ sanity checks and env info ]--------------------------------------------

$pwd = rtrim(shell_exec("pwd"), "\n");

$expected_dirs = explode(" ", "../boot ../kernelconfigs ../minibsd ../patches ../tools ".
							"../../captiveportal ../../etc ../../phpconf ../../webgui");
foreach($expected_dirs as $expected_dir) {
	if(!file_exists($expected_dir)) {
		_log("FATAL: missing directory ($expected_dir)\n".
			" - m0n0builder.php must be in /path/to/m0n0/svn/build/dev/");
		exit();
	}
}

if(!file_exists("packages")) {
	mkdir("packages");
}
if(!file_exists("images")) {
	mkdir("images");
}
if(!file_exists("mfsroots")) {
	mkdir("mfsroots");
}

$error_codes = array(
	/* 0 */ "",
	/* 1 */ "not enough arguments!",
	/* 2 */ "invalid argument!",
	/* 3 */ "invalid platform specified!",
	/* 4 */ "invalid kernel specified!",
	/* 5 */ "invalid image specified!",
	/* 6 */ "image already exists!"
);


// --[ the functions! ]--------------------------------------------------------

$h["patch kernel"] = "patches the kernel sources with any changes needed by m0n0wall";
function patch_kernel() {
	global $pwd;
	
	_exec("cd /usr/src; patch -p0 < $pwd/../patches/kernel/kernel-6.patch");
	_log("patched kernel");
	
	_exec("cd /usr/src/sys; patch -p0 < $pwd/../patches/kernel/racoon-nattraversal-freebsd6.patch");
	_log("patched racoon nat-traversal");
}


$h["patch syslog"] = "patches circular logging support into syslog";
function patch_syslogd() {
	global $pwd;

	_exec("cd /usr/src; patch < $pwd/../patches/user/syslogd.c.patch");
	_exec("cd /usr/src/usr.sbin; tar xfvz $pwd/../patches/user/clog-1.0.1.tar.gz");

	_log("patched syslogd");
}


$h["patch bootloader"] = "patches the bootloader to fix some problems with terminal output";
function patch_bootloader() {
	global $pwd;
	
	_exec("cd /sys/boot/i386/libi386; patch < $pwd/../patches/boot/libi386.patch");
	
	_log("patched bootloader");
}


$h["build kernel"] = "(re)builds and compresses the specified platform's kernel ($platform_list)"; 
function build_kernel($platform) {
	global $pwd, $platforms;
	
	// sanity checks
	if(array_search($platform, $platforms) === false) {
		_usage(3);
	}
	
	if($platform == "generic-pc-cdrom") {
		$platform = "generic-pc";
	}
	$platform == "generic-pc" ?
		$kernel = "M0N0WALL_GENERIC" :
		$kernel = "M0N0WALL_" . strtoupper($platform);
				
	_exec("cp ../kernelconfigs/$kernel* /sys/i386/conf/");
	if(file_exists("/sys/i386/compile/$kernel")) {
		_exec("rm -rf /sys/i386/compile/$kernel");
	}
	_exec("cd /sys/i386/conf/; config $kernel");
	_exec("cd /sys/i386/compile/$kernel; make cleandepend; make depend; make");
	_exec("gzip -9 /sys/i386/compile/$kernel/kernel");

	_log("built kernel for $platform");
}


$h["build kernels"] = "(re)builds and compresses all kernels";
function build_kernels() {
	global $platforms;
	
	foreach($platforms as $platform) {
		if($platform == "generic-pc-cdrom") {
			continue;
		}
		build_kernel($platform);
	}
}


$h["build syslogd"] = "(re)builds syslogd";
function build_syslogd() {

	_exec("cd /usr/src/usr.sbin/syslogd; make clean; make");
	
	_log("built syslogd");	
}


$h["build clog"] = "(re)builds the circular logging binary which optimizes logging on devices with limited memory";
function build_clog() {

	_exec("cd /usr/src/usr.sbin/clog; make clean; make obj; make");	
	
	_log("built clog");
}


$h["build php"] = "(re)builds php and radius extension, also installs and configures autoconf if not already present";
function build_php() {
	global $php_version, $radius_version;

	if(!file_exists("/usr/local/bin/autoconf")) {
		_exec("cd /usr/ports/devel/autoconf213; make install clean");
		_exec("ln -s /usr/local/bin/autoconf213 /usr/local/bin/autoconf");
		_exec("ln -s /usr/local/bin/autoheader213 /usr/local/bin/autoheader");
		_log("installed autoconf");
	}
	
	if(!file_exists("packages/$php_version")) {
		// TODO: this is ugly, need a direct link and some sort of smart mirror selection
		_exec("cd packages; fetch http://de2.php.net/get/$php_version.tar.gz/from/this/mirror");
		_exec("cd packages; mv mirror $php_version.tar.gz");
		_exec("cd packages; tar zxf $php_version.tar.gz");
		_log("fetched and untarred $php_version");
		
		_exec("cd packages/$php_version/ext; fetch http://m0n0.ch/wall/downloads/freebsd-4.11/$radius_version.tgz");
		_exec("cd packages/$php_version/ext; tar zxf $radius_version.tgz");
		_exec("cd packages/$php_version/ext; mv $radius_version radius");
		_log("fetched and untarred $radius_version");
	}
	_exec("cd packages/$php_version; rm configure");
	_exec("cd packages/$php_version; ./buildconf --force");
	_exec("cd packages/$php_version; ./configure --without-mysql --with-pear ".
		"--with-openssl --enable-discard-path --enable-radius --enable-sockets --enable-bcmath");
	_exec("cd packages/$php_version; make");
	
	_log("built php");
}


$h["build minihttpd"] = "(re)builds and patches mini_httpd";
function build_minihttpd() {
	global $pwd, $mini_httpd_version;
	
	if(!file_exists("packages/$mini_httpd_version")) {
		_exec("cd packages; fetch http://www.acme.com/software/mini_httpd/$mini_httpd_version.tar.gz");
		_exec("cd packages; tar zxf $mini_httpd_version.tar.gz");
		_log("fetched and untarred $mini_httpd_version");
	}
	if(!_is_patched($mini_httpd_version)) {
		_exec("cd packages/$mini_httpd_version; patch < $pwd/../patches/packages/mini_httpd.patch");
		_stamp_package_as_patched($mini_httpd_version);
	}
	_exec("cd packages/$mini_httpd_version; make clean; make");

	_log("built minihttpd");
}


$h["build dhcpserver"] = "(re)builds the ISC DHCP server (NOTE: dialog must be confirmed)";
function build_dhcpserver() {
	
	/* TODO: automate compile */
	_exec("cd /usr/ports/net/isc-dhcp3-server; make clean; make WITHOUT_DHCP_LDAP_SSL=YES WITHOUT_DHCP_PARANOIA=YES WITHOUT_DHCP_JAIL=YES");

	_log("built dhcp server");
}


$h["build dhcprelay"] = "(re)builds the ISC DHCP relay";
function build_dhcprelay() {
	
	_exec("cd /usr/ports/net/isc-dhcp3-relay; make clean; make");

	_log("built dhcp relay");
}


$h["build dnsmasq"] = "(re)builds Dnsmasq (DNS forwarder for NAT firewalls) (NOTE: dialog must be confirmed)";
function build_dnsmasq() {
	
	/* TODO: automate compile after setting */
	_exec("cd /usr/ports/dns/dnsmasq; make clean; make");
	
	_log("built dnsmasq");
}


$h["build msntp"] = "(re)builds msntp (NTP client)";
function build_msntp() {
	
	_exec("cd /usr/ports/net/msntp; make clean; make");
	
	_log("built msntp");
}


$h["build wol"] = "(re)builds wol (wake-on-lan client)";
function build_wol() {
	global $wol_version;

	if(!file_exists("packages/$wol_version")) {
		_exec("cd packages; fetch http://heanet.dl.sourceforge.net/sourceforge/ahh/$wol_version.tar.gz");
		_exec("cd packages; tar zxf $wol_version.tar.gz");
		_log("fetched and untarred $wol_version");
	}
	_exec("cd packages/$wol_version; ./configure --disable-nls");
	_exec("cd packages/$wol_version; make");

	_log("built wol");
}


$h["build ezipupdate"] = "(re)builds and patches ez-ipupdate (dynamic dns update client)";
function build_ezipupdate() {
	global $pwd, $ez_ipupdate_version;
	
	if(!file_exists("packages/$ez_ipupdate_version")) {
		_exec("cd packages; fetch http://dyn.pl/client/UNIX/ez-ipupdate/$ez_ipupdate_version.tar.gz");
		_exec("cd packages; tar zxf $ez_ipupdate_version.tar.gz");
		_log("fetched and untarred $ez_ipupdate_version");
	}
	if(!_is_patched($ez_ipupdate_version)) {
		_exec("cd packages/$ez_ipupdate_version; patch < $pwd/../patches/packages/ez-ipupdate.c.patch");
		_stamp_package_as_patched($ez_ipupdate_version);
	}	
	_exec("cd packages/$ez_ipupdate_version; ./configure");
	_exec("cd packages/$ez_ipupdate_version; make");

	_log("built ez-ipupdate");
}


$h["build bpalogin"] = "(re)builds BPALogin (Big Pond client)";
function build_bpalogin() {
	global $bpalogin_version;
	
	if(!file_exists("packages/$bpalogin_version")) {
		_exec("cd packages; fetch http://bpalogin.sourceforge.net/download/$bpalogin_version.tar.gz");
		_exec("cd packages; tar zxf $bpalogin_version.tar.gz");
		_log("fetched and untarred $bpalogin_version");
	}
	_exec("cd packages/$bpalogin_version; ./configure");
	_exec("cd packages/$bpalogin_version; make");

	_log("built bpalogin");
}


$h["build racoon"] = "(re)builds the ipsec-tools version of racoon (NOTE: this is currently done really hackily)";
function build_racoon() {
	global $pwd, $ipsec_tools_version;
	
	// TODO: automate editing CONFIGURE_ARGS in the Makefile: 
	// remove --enable-debug and --enable-ipv6 options
	// add --without-readline
	
	// TODO: mklibs.pl fails on this because the library has already been added by hand
	// hacked to install lib temporarily

	// TODO: ugly ugly ugly...make clean, make, make clean, make install!!
	_exec("cd /usr/ports/security/ipsec-tools; make clean; make");
	_exec("cd /usr/ports/security/ipsec-tools/work/$ipsec_tools_version; ".
			"patch < $pwd/../patches/packages/$ipsec_tools_version.patch");
	_exec("cd /usr/ports/security/ipsec-tools/work/$ipsec_tools_version; make clean; make install");
	
	_log("built and patched racoon");

}


$h["build mpd"] = "(re)builds and patches MPD (Multi-link PPP daemon)";
function build_mpd() {
	global $pwd, $mpd_version;
	
	// TODO: ugly...still need to better judge the port status
	_exec("cd /usr/ports/net/mpd; make clean; make");
	_exec("cd /usr/ports/net/mpd/work/$mpd_version; patch < $pwd/../patches/packages/mpd.patch");
	_exec("cd /usr/ports/net/mpd/work/$mpd_version; make");
	
	_log("built and patched MPD");
}


$h["build ucdsnmp"] = "(re)builds and patches UCD-SNMP (now NET-SNMP)";
function build_ucdsnmp() {
	global $pwd, $ucd_snmp_version;

	if(!file_exists("packages/$ucd_snmp_version")) {
		_exec("cd packages; fetch http://kent.dl.sourceforge.net/sourceforge/net-snmp/$ucd_snmp_version.tar.gz");
		_exec("cd packages; tar zxf $ucd_snmp_version.tar.gz");
		_log("fetched and untarred $ucd_snmp_version");
	}
	if(!_is_patched($ucd_snmp_version)) {
		_exec("cd packages/$ucd_snmp_version; patch < $pwd/../patches/packages/ucd-snmp.patch");
		_stamp_package_as_patched($ucd_snmp_version);
	}
	_prompt("All of the following prompts can all be answered with their default values.", 5);

	_exec("cd packages/$ucd_snmp_version; ./configure  --without-openssl --disable-debugging --enable-static ".
		"--enable-mini-agent --disable-privacy --disable-testing-code ".
		"--disable-shared-version --disable-shared --disable-ipv6 ".
		"'--with-out-transports=TCP Unix' ".
		"'--with-mib-modules=mibII/interfaces mibII/var_route ucd-snmp/vmstat_freebsd2'");
	_exec("cd packages/$ucd_snmp_version; make");

	_log("built UCD-SNMP");
}


$h["build tools"] = "(re)builds the little \"helper tools\" that m0n0wall needs (choparp, stats.cgi, minicron, verifysig)";
function build_tools() {
	
	_exec("cd ../tools; gcc -o choparp choparp.c");
	_log("built choparp");
	
	_exec("cd ../tools; gcc -o stats.cgi stats.c");
	_log("built stats.cgi");
	
	_exec("cd ../tools; gcc -o minicron minicron.c");
	_log("built minicron");
	
	_exec("cd ../tools; gcc -o verifysig -lcrypto verifysig.c");
	_log("built verifysig");
}


$h["build bootloader"] = "(re)builds the bootloader files and stores them in ./boot";
function build_bootloader() {
	
	_exec("cd /sys/boot; make clean; make obj; make");
	
	_log("compiled boot loader");
}


$h["build packages"] = "(re)builds all necessary packages";
function build_packages() {

	build_php();
	build_minihttpd();
	build_wol();
	build_ezipupdate();
	build_bpalogin();
	build_ucdsnmp();
}

$h["build ports"] = "(re)builds all necessary ports";
function build_ports() {
	
	build_dnsmasq();
	build_msntp();
	build_dhcpserver();
	build_dhcprelay();
	build_racoon();
	build_mpd();
}

$h["build everything"] = "(re)builds all packages, kernels and the bootloader";
function build_everything() {

	build_packages();
	build_ports();
	build_kernels();
	build_bootloader();
}


$h["create"] = "creates the directory structure for the given \"image_name\"";
function create($image_name) {
	
	_exec("mkdir $image_name");
	_exec("cd $image_name; mkdir lib bin cf conf.default dev etc ftmp mnt libexec proc root sbin tmp usr var");
	_exec("cd $image_name; mkdir etc/inc");
	_exec("cd $image_name; ln -s /cf/conf conf");
	_exec("cd $image_name/usr; mkdir bin lib libexec local sbin share");
	_exec("cd $image_name/usr/local; mkdir bin captiveportal lib sbin www");
	_exec("cd $image_name/usr/local; ln -s /var/run/htpasswd www/.htpasswd");
	
	_log("created directory structure");
}


$h["populate base"] = "populates the base system binaries for the given \"image_name\"";
function populate_base($image_name) {

	_exec("perl ../minibsd/mkmini.pl ../minibsd/m0n0wall.files / $image_name");
	
	_log("added base system binaries");
}


$h["populate etc"] = "populates /etc and appropriately links /etc/resolv.conf and /etc/hosts for the given \"image_name\"";
function populate_etc($image_name) {
	
	_exec("cp -p files/etc/* $image_name/etc/");
	_exec("cp -p ../../etc/rc* $image_name/etc/");
	_exec("cp ../../etc/pubkey.pem $image_name/etc/");
	_log("added etc");
	
	// TODO: should check here to see if these links already exist
	_exec("ln -s /var/etc/resolv.conf $image_name/etc/resolv.conf");
	_exec("ln -s /var/etc/hosts $image_name/etc/hosts");
	_log("added resolv.conf and hosts symlinks");
	
}


$h["populate defaultconf"] = "adds the default xml configuration file to the given \"image_name\"";
function populate_defaultconf($image_name) {
	
	_exec("cp ../../phpconf/config.xml $image_name/conf.default/");
	
	_log("added default config.xml");
}


$h["populate zoneinfo"] = "adds timezone info to the given \"image_name\"";
function populate_zoneinfo($image_name) {
	
	_exec("cp files/zoneinfo.tgz $image_name/usr/share/");
	
	_log("added zoneinfo.tgz");
}


$h["populate syslogd"] = "adds syslogd to the given \"image_name\"";
function populate_syslogd($image_name) {
	global $pwd;
	
	_exec("cd /usr/src/usr.sbin/syslogd; install -s /usr/obj/usr/src/usr.sbin/syslogd/syslogd $pwd/$image_name/usr/sbin");

	_log("added syslogd");
}


$h["populate clog"] = "adds circular logging to the given \"image_name\"";
function populate_clog($image_name) {
	global $pwd;
	
	_exec("cd /usr/src/usr.sbin/clog; install -s /usr/obj/usr/src/usr.sbin/clog/clog $pwd/$image_name/usr/sbin");

	_log("added clog");
}


$h["populate php"] = "adds the php interpreter to the given \"image_name\"";
function populate_php($image_name) {
	global $pwd, $php_version;
	
	_exec("cd packages/$php_version/; install -s sapi/cgi/php $pwd/$image_name/usr/local/bin");
	_exec("cp files/php.ini $image_name/usr/local/lib/");

	_log("added php");
}


$h["populate minihttpd"] = "adds the mini-httpd server to the given \"image_name\"";
function populate_minihttpd($image_name) {
	global $pwd, $mini_httpd_version;
	
	_exec("cd packages/$mini_httpd_version; install -s mini_httpd $pwd/$image_name/usr/local/sbin");
	
	_log("added mini_httpd");
}


$h["populate dhclient"] = "adds the ISC DHCP client to the given \"image_name\"";
function populate_dhclient($image_name) {
	global $pwd;
	
	_exec("cp /sbin/dhclient $image_name/sbin/");
	_exec("cp files/dhclient-script $image_name/sbin/");
	
	_log("added dhclient");
}


$h["populate dhcpserver"] = "adds the ISC DHCP server to the given \"image_name\"";
function populate_dhcpserver($image_name) {
	global $pwd;
	
	_exec("cd /usr/ports/net/isc-dhcp3-server; install -s work/dhcp-*/work.freebsd/server/dhcpd $pwd/$image_name/usr/local/sbin");
	
	_log("added dhcp server");
}


$h["populate dhcprelay"] = "adds the ISC DHCP relay to the given \"image_name\"";
function populate_dhcprelay($image_name) {
	global $pwd;
	
	_exec("cd /usr/ports/net/isc-dhcp3-relay; install -s work/dhcp-*/work.freebsd/relay/dhcrelay $pwd/$image_name/usr/local/sbin");
	
	_log("added dhcp relay");
}


$h["populate dnsmasq"] = "adds Dnsmasq (DNS forwarder) to the given \"image_name\"";
function populate_dnsmasq($image_name) {
	global $pwd;
	
	_exec("cd /usr/ports/dns/dnsmasq; install -s work/dnsmasq-*/src/dnsmasq $pwd/$image_name/usr/local/sbin");
	
	_log("added dnsmasq");
}


$h["populate msntp"] = "adds msntp (NTP client) to the given \"image_name\"";
function populate_msntp($image_name) {
	global $pwd;
	
	_exec("cd /usr/ports/net/msntp; install -s work/msntp-*/msntp $pwd/$image_name/usr/local/bin");
	
	_log("added msntp");
}


$h["populate wol"] = "adds wol (wake on lan client) to the given \"image_name\"";
function populate_wol($image_name) {
	global $pwd, $wol_version;

	_exec("cd packages/$wol_version; install -s src/wol $pwd/$image_name/usr/local/bin");
	
	_log("added wol");
}


$h["populate ezipupdate"] = "adds ez-ipupdate (dynamic dns client) to the given \"image_name\"";
function populate_ezipupdate($image_name) {
	global $pwd, $ez_ipupdate_version;
	
	_exec("cd packages/$ez_ipupdate_version; install -s ez-ipupdate $pwd/$image_name/usr/local/bin");
	
	_log("added ez-ipupdate");
}


$h["populate bpalogin"] = "adds bpalogin (Big Pond client) to the given \"image_name\"";
function populate_bpalogin($image_name) {
	global $pwd, $bpalogin_version;
	
	_exec("cd packages/$bpalogin_version; install -s bpalogin $pwd/$image_name/usr/local/sbin");

	_log("added bpalogin");
}


$h["populate mpd"] = "adds MPD (Multi-link PPP daemon) to the given \"image_name\"";
function populate_mpd($image_name) {
	global $pwd;
	
	_exec("cd /usr/ports/net/mpd; install -s work/mpd-*/src/mpd $pwd/$image_name/usr/local/sbin");
	
	_log("added mpd");
}


$h["populate racoon"] = "adds racoon to the given \"image_name\"";
function populate_racoon($image_name) {
	global $pwd, $ipsec_tools_version;
	
	_exec("cd /usr/ports/security/ipsec-tools; install -s work/$ipsec_tools_version/src/racoon/.libs/racoon $pwd/$image_name/usr/local/sbin");
	_exec("cd /usr/ports/security/ipsec-tools; install -s work/$ipsec_tools_version/src/libipsec/.libs/libipsec.so.0 $pwd/$image_name/usr/local/lib");
	_exec("cp /usr/ports/security/ipsec-tools/work/$ipsec_tools_version/src/setkey/setkey $image_name/usr/local/sbin/");
	
	_log("added racoon");
}


$h["populate ucdsnmp"] = "adds UCD-SNMP to the given \"image_name\"";
function populate_ucdsnmp($image_name) {
	global $pwd, $ucd_snmp_version;
	
	_exec("cd packages/$ucd_snmp_version; install -s agent/snmpd $pwd/$image_name/usr/local/sbin");
	
	_log("added ucd-snmp");
}


$h["populate tools"] = "adds the m0n0wall \"helper tools\" to the given \"image_name\"";
function populate_tools($image_name) {
	global $pwd;
	
	_exec("cd ../tools; install -s choparp $pwd/$image_name/usr/local/sbin");
	_log("added choparp");
	
	_exec("cd ../tools; install -s stats.cgi $pwd/$image_name/usr/local/www");
	_log("added stats.cgi");
	
	_exec("cd ../tools; install -s minicron $pwd/$image_name/usr/local/bin");
	_log("added minicron");
	
	_exec("cd ../tools; install -s verifysig $pwd/$image_name/usr/local/bin");
	_log("added verifysig");
	
	_exec("cd ../tools; install runmsntp.sh $pwd/$image_name/usr/local/bin");
	_log("added runmsntp.sh");
	
	_exec("cd ../tools; install ppp-linkup vpn-linkdown vpn-linkup $pwd/$image_name/usr/local/sbin");
	_log("added linkup scripts");
}


$h["populate phpconf"] = "adds the php configuration system to the given \"image_name\"";
function populate_phpconf($image_name) {
	
	_exec("cp ../../phpconf/rc* $image_name/etc/");
	_exec("cp ../../phpconf/inc/* $image_name/etc/inc/");
	
	_log("added php conf scripts");
}


$h["populate webgui"] = "adds the php webgui files to the given \"image_name\"";
function populate_webgui($image_name) {
	
	_exec("cp ../../webgui/* $image_name/usr/local/www/");
	
	_log("added webgui");
}


$h["populate captiveportal"] = "adds the captiveportal scripts to the given \"image_name\"";
function populate_captiveportal($image_name) {
	
	_exec("cp ../../captiveportal/* $image_name/usr/local/captiveportal/");
	
	_log("added captiveportal");
}


$h["populate libs"] = "adds the required libraries (using mklibs.pl) to the given \"image_name\"";
function populate_libs($image_name) {
	global $pwd;
	
	_exec("perl ../minibsd/mklibs.pl $pwd/$image_name > tmp.libs");
	_exec("perl ../minibsd/mkmini.pl tmp.libs / $pwd/$image_name");
	_exec("rm tmp.libs");
	
	_log("added libraries");	
}


$h["populate everything"] = "adds all packages, scripts and config files to the given \"image_name\"";
function populate_everything($image_name) {

	$funcs = get_defined_functions();
	$funcs = $funcs['user'];

	foreach($funcs as $func) {
		if($func[0] == '_') {
			continue;
		}
		$func = explode("_", $func);
 		if($func[0] == "populate" && $func[1] != "everything") {
			$f = "populate_" . $func[1];
			$f($image_name);
		}
	}


	_exec("chmod 755 $image_name/etc/rc*");
	_exec("chmod 644 $image_name/etc/pubkey.pem");
	
	_exec("chmod 644 $image_name/etc/inc/*");
	
	_exec("chmod 644 $image_name/conf.default/config.xml");

	_exec("chmod 644 $image_name/usr/local/www/*");
	_exec("chmod 755 $image_name/usr/local/www/*.php");
	_exec("chmod 755 $image_name/usr/local/www/*.cgi");
	
	_exec("chmod 644 $image_name/usr/local/captiveportal/*");
	_exec("chmod 755 $image_name/usr/local/captiveportal/*.php");

}

$h["package"] = "package the specified image directory into an .img for the specified platform and stamp as version";
function package($platform, $version, $image_name) {
	
	_log("packaging $image_name v($version) for $platform...");
	
	if(!file_exists("tmp")) {
		mkdir("tmp");
		mkdir("tmp/mnt");
	}

	// mfsroots
	_exec("dd if=/dev/zero of=tmp/mfsroot bs=1M count=13");
	_exec("mdconfig -a -t vnode -f tmp/mfsroot -u 0");

	_exec("bsdlabel -rw md0 auto");
	_exec("newfs -O 1 -b 8192 -f 1024 -o space -m 0 /dev/md0c");

	_exec("mount /dev/md0c tmp/mnt");
	_exec("cd tmp/mnt; tar -cf - -C ../../$image_name ./ | tar -xpf -");
	
	// modules
	$platform == "generic-pc" ?
		$kernel = "M0N0WALL_GENERIC" :
		$kernel = "M0N0WALL_" . strtoupper($platform);

	mkdir("tmp/mnt/boot");
	mkdir("tmp/mnt/boot/kernel");
	if($platform == "generic-pc") {
		_exec("cp /sys/i386/compile/$kernel/modules/usr/src/sys/modules/acpi/acpi/acpi.ko tmp/mnt/boot/kernel/");
	}
	_exec("cp /sys/i386/compile/$kernel/modules/usr/src/sys/modules/dummynet/dummynet.ko tmp/mnt/boot/kernel/");
	_exec("cp /sys/i386/compile/$kernel/modules/usr/src/sys/modules/ipfw/ipfw.ko tmp/mnt/boot/kernel/");
	
	_exec("echo \"$version\" > tmp/mnt/etc/version");
	_exec("echo `date` > tmp/mnt/etc/version.buildtime");
	_exec("echo $platform > tmp/mnt/etc/platform");

	_exec("umount tmp/mnt");
	_exec("mdconfig -d -u 0");
	_exec("gzip -9 tmp/mfsroot");
	_exec("mv tmp/mfsroot.gz mfsroots/$platform-$version-$image_name.gz");

	// .img
	if($platform != "generic-pc-cdrom") {
		$platform == "generic-pc" ?
			_exec("dd if=/dev/zero of=tmp/image.bin bs=1k count=10240") :	
			_exec("dd if=/dev/zero of=tmp/image.bin bs=1k count=7808");
		_exec("mdconfig -a -t vnode -f tmp/image.bin -u 0");
		_exec("bsdlabel -Brw -b /usr/obj/usr/src/sys/boot/i386/boot2/boot md0 auto");
		_exec("newfs -O 1 -b 8192 -f 1024 -o space -m 0 /dev/md0a");
		_exec("mount /dev/md0a tmp/mnt");
		_exec("cp mfsroots/$platform-$version-$image_name.gz tmp/mnt/mfsroot.gz");
		
		// boot
		mkdir("tmp/mnt/boot");
		mkdir("tmp/mnt/boot/kernel");
	    _exec("cp /usr/obj/usr/src/sys/boot/i386/loader/loader tmp/mnt/boot/");
		_exec("cp ../boot/$platform/loader.rc tmp/mnt/boot/");

		// conf
		mkdir("tmp/mnt/conf");
		_exec("cp ../../phpconf/config.xml tmp/mnt/conf");
		_exec("cp /sys/i386/compile/$kernel/kernel.gz tmp/mnt/kernel.gz");		
		_exec("umount tmp/mnt");
		_exec("mdconfig -d -u 0");
		_exec("gzip -9 tmp/image.bin");
		_exec("mv tmp/image.bin.gz images/$platform-$version-$image_name.img");

	// .iso
	} else {
		
	}
	
	_exec("rm -rf tmp");
}



function _stamp_package_as_patched($package_version) {
	
	touch("packages/$package_version/$package_version.patched");
	_log("patched $package_version");
}

function _is_patched($package_version) {
	
	return(file_exists("packages/$package_version/$package_version.patched"));
}


function _exec($cmd) {
	$ret = 0;
	passthru($cmd, $ret);
	if($ret != 0) {
		_log("COMMAND FAILED: $cmd");
		exit();
	}
}


function _log($msg) {
	print "$msg\n";
}


function _prompt($msg, $duration=0) {
	
	$msg = wordwrap(" - $msg", 74, "\n - ");
	if($duration) {
		print "--[ HELLO THERE ]-------------------------------------------------------------\n\n";
	}	
	print "$msg\n\n";
	if($duration) {
		print "--[ T-MINUS ";
		print "$duration";
		$i = $duration-1;
		for($i; $i>0; $i--) {
			sleep(1);
			print ", $i";
		}
		sleep(1);
		print "\n\n";
	}
}


function _usage($err=0) {
	global $error_codes;

	if($err != 0) {
		_log($error_codes[$err]);
	}
	
	print "./m0n0builder.php patch bootloader\n";
	print "./m0n0builder.php patch kernel\n";
	print "./m0n0builder.php patch syslogd\n";
	print "./m0n0builder.php build kernel kernel_name\n";
	print "./m0n0builder.php build kernels\n";
	print "./m0n0builder.php build bootloader\n";
	print "./m0n0builder.php build tools\n";
	print "./m0n0builder.php build package_name\n";
	print "./m0n0builder.php build everything\n";
	print "./m0n0builder.php populate everything package_name\n";
	print "./m0n0builder.php package platform_name version_string image_name\n";
	print "./m0n0builder.php package all version_string image_name\n";
	
	print "Help is available by prefixing the command with \"help\" (i.e. help create)\n";
	
	exit($err);
}


//TODO: I can generate these...
$h["patch"] = "available patch options: bootloader, kernel, syslogd";
$h["build"] = "available build options: kernel, kernels, syslogd, clog, php, minihttpd, ".
	"dhcpserver, dhcprelay, dnsmasq, msntp, wol, ezipupdate, bpalogin, racoon, mpd, ".
	"ucdsnmp, tools, bootloader, everything";
$h["populate"] = "available populate options: base, etc, defaultconf, zoneinfo, syslogd, ".
	"clog, php, minihttpd, dhclient, dhcpserver, dhcprelay, dnsmasq, msntp, wol, ".
	"ezipupdate, bpalogin, mpd, racoon, ucdsnmp, tools, phpconf, webgui, captiveportal, ".
	"libs, everything";




// --[ command line parsing ]--------------------------------------------------

// nothing to do, here's what's possible
if($argc == 1) {
	_usage();

// here's some help if it's available
} else if($argv[1] == "help") {
	if($argc == 2) {
		_usage();
	}
	$c = implode(" ", array_slice($argv, 2));
	array_key_exists($c, $h) ? 
		_prompt($h[$c]) : 
		print "no help available on ($c)! :(\n";
	
// create a new image directory
} else if($argv[1] == "create") {
	file_exists($argv[2]) ?
		_usage(6) :
		create($argv[2]);
	
// patch functions are all defined with no arguments
} else if($argv[1] == "patch") {
	$f = implode("_", array_slice($argv, 1));
	function_exists($f) ?
		$f() :
		_usage(2);		
	
// build functions are all defined with no arguments except for "build_kernel"
} else if($argv[1] == "build") {
	if($argv[2] == "kernel") {
		build_kernel($argv[3]);
	} else {
		$f = implode("_", array_slice($argv, 1));
		function_exists($f) ?
			$f() :
			_usage(2);
	}

// populate functions are all defined with a single argument (image_name directory)
} else if($argv[1] == "populate") {
	$f = implode("_", array_slice($argv, 1, 2));
	if(!function_exists($f)) {
		_usage(2);
	}
	file_exists($argv[3]) ?
		$image_name = rtrim($argv[3], "/") :
		_usage(5);
	$f($image_name);

// the package function is defined with two arguments (platform, image_name)
} else if($argv[1] == "package") {
	file_exists($argv[4]) ?
		$image_name = rtrim($argv[4], "/") :
		_usage(5);
	if($argv[2] == "all") {
		foreach($platforms as $platform) {
			package($platform, $argv[3], $image_name);			
		}
	} else if(in_array($argv[2], $platforms)) {
		package($argv[2], $argv[3], $image_name);
	} else {
		_usage(3);
	}

// hmmm, don't have any verbs like that!
} else {
	_usage(2);
}

exit();

?>
