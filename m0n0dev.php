#!/usr/local/bin/php -f
<?php
/*
    m0n0dev.php (http://www.askozia.com/m0n0wall/m0n0dev.php)
    
    Copyright (C) 2007 IKT <http://www.itison-ikt.de> 
    All rights reserved.
    
    Authors:
        Michael Iedema <michael@askozia.com>.
    
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

// Please set me to the path you checked out the m0n0wall FreeBSD 6 branch to.
$dirs['mwroot'] = "/root/m0n0wall";	// no trailing slash please!

// --[ package versions ]------------------------------------------------------

$php_version			= "php-4.4.7";
$radius_version			= "radius-1.2.5";
$mini_httpd_version		= "mini_httpd-1.19";
$wol_version			= "wol-0.7.1";
$ez_ipupdate_version	= "ez-ipupdate-3.0.11b8";
$bpalogin_version		= "bpalogin-2.0.2";
$ucd_snmp_version		= "ucd-snmp-4.2.7";
$mpd_version			= "mpd-3.18";
$ipsec_tools_version 	= "ipsec-tools-0.7";
$siproxd_version 	    = "siproxd-0.6.0";


// --[ image sizes ]-----------------------------------------------------------

$mfsroot_pad	= 2304;     // this gives roughly 15MB and matches official >=1.3b3
$image_pad		= 1024;


// --[ possible platforms and kernels ]----------------------------------------

$platform_list	= "net45xx net48xx wrap generic-pc generic-pc-cdrom";//generic-pc-smp";
$platforms		= explode(" ", $platform_list);


// --[ sanity checks and env info ]--------------------------------------------

$dirs['pwd']			= rtrim(shell_exec("pwd"), "\n");
$dirs['boot']			= $dirs['mwroot'] . "/build/boot";
$dirs['kernelconfigs']	= $dirs['mwroot'] . "/build/kernelconfigs";
$dirs['minibsd']		= $dirs['mwroot'] . "/build/minibsd";
$dirs['patches']		= $dirs['mwroot'] . "/build/patches";
$dirs['tools']			= $dirs['mwroot'] . "/build/tools";
$dirs['captiveportal']	= $dirs['mwroot'] . "/captiveportal";
$dirs['etc']			= $dirs['mwroot'] . "/etc";
$dirs['phpconf']		= $dirs['mwroot'] . "/phpconf";
$dirs['webgui']			= $dirs['mwroot'] . "/webgui";
$dirs['files']			= $dirs['pwd'] . "/files";

// check to make sure that the directories we expect are there
foreach($dirs as $expected_dir) {
	if(!file_exists($expected_dir)) {
		_log("FATAL: missing directory ($expected_dir)\n".
			"Did you set the \"mwroot\" at the top of this script to the correct path?");
		exit(1);
	}
}

// create the work directory
if(!file_exists("work")) {
	mkdir("work");
}

// ...and subdirectories
$dirs['packages'] = $dirs['pwd']."/work/packages";
$dirs['images'] = $dirs['pwd']."/work/images";
$dirs['mfsroots'] = $dirs['pwd']."/work/mfsroots";

foreach($dirs as $dir) {
	if(!file_exists($dir)) {
		mkdir($dir);
	}	
}


// --[ the functions! ]--------------------------------------------------------

$h["patch kernel"] = "patches the kernel sources with any changes needed by m0n0wall";
function patch_kernel() {
	global $dirs;
	
	_exec("cd /usr/src; patch -p0 < ". $dirs['patches'] ."/kernel/kernel-6.patch");
	_log("patched kernel");
	
	_exec("cd /usr/src/sys; patch -p0 < ". $dirs['patches'] ."/kernel/racoon-nattraversal-freebsd6.patch");
	_log("patched racoon nat-traversal");
}


$h["patch syslog"] = "patches circular logging support into syslog";
function patch_syslogd() {
	global $dirs;

	_exec("cd /usr/src; patch < ". $dirs['patches'] ."/user/syslogd.c.patch");
	_exec("cd /usr/src/usr.sbin; tar xfvz ". $dirs['patches'] ."/user/clog-1.0.1.tar.gz");

	_log("patched syslogd");
}


$h["patch bootloader"] = "patches the bootloader to fix some problems with terminal output";
function patch_bootloader() {
	global $dirs;
	
	_exec("cd /sys/boot/i386/libi386; patch < ". $dirs['files'] ."/libi386.patch");
	
	_log("patched bootloader");
}

$h["patch hostapd"] = "patches hostapd to add PID support";
function patch_hostapd() {
	global $dirs;
	
	_exec("cd /usr/src; patch < ". $dirs['patches'] ."/user/hostapd.patch");
	
	_log("patched hostapd");
}


$h["patch everything"] = "patches the bootloader, kernel and syslogd";
function patch_everything() {
	
	patch_kernel();
	patch_syslogd();
	patch_bootloader();
	patch_hostapd();
}


$h["build kernel"] = "(re)builds and compresses the specified platform's kernel ($platform_list)"; 
function build_kernel($platform) {
	global $dirs;
	
	$kernel = _platform_to_kernel($platform);

	_exec("cp ". $dirs['kernelconfigs'] ."/M0N0WALL_* /sys/i386/conf/");
	_exec("cp ". $dirs['files'] ."/M0N0WALL_GENERIC_SMP* /sys/i386/conf/");
	
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

$h["build hostapd"] = "(re)builds the hostapd binary";
function build_hostapd() {

	_exec("cd /usr/src/usr.sbin/wpa/hostapd; make clean; make; make install");	
	
	_log("built hostapd");
}


$h["build php"] = "(re)builds php and radius extension, also installs and configures autoconf if not already present";
function build_php() {
	global $dirs, $php_version, $radius_version;

	if(!file_exists("/usr/local/bin/autoconf")) {
		_exec("cd /usr/ports/devel/autoconf213; make install clean");
		_exec("ln -s /usr/local/bin/autoconf213 /usr/local/bin/autoconf");
		_exec("ln -s /usr/local/bin/autoheader213 /usr/local/bin/autoheader");
		_log("installed autoconf");
	}
	
	if(!file_exists($dirs['packages'] ."/$php_version")) {
		_exec("cd ". $dirs['packages'] ."; ".
				"fetch http://br.php.net/distributions/$php_version.tar.gz;" .
				"tar zxf $php_version.tar.gz");
		_log("fetched and untarred $php_version");
		
		_exec("cd ". $dirs['packages'] ."/$php_version/ext; ".
				"fetch http://m0n0.ch/wall/downloads/freebsd-4.11/$radius_version.tgz; ".
				"tar zxf $radius_version.tgz; ".
				"mv $radius_version radius");
		_log("fetched and untarred $radius_version");
	}
	_exec("cd ". $dirs['packages'] ."/$php_version; ".
			"rm configure; ".
			"./buildconf --force; ".
			"./configure --without-mysql --with-pear --with-openssl --enable-discard-path --enable-radius --enable-sockets --enable-bcmath; ".
			"make");
	
	_log("built php");
}


$h["build minihttpd"] = "(re)builds and patches mini_httpd";
function build_minihttpd() {
	global $dirs, $mini_httpd_version;
	
	if(!file_exists($dirs['packages'] ."/$mini_httpd_version")) {
		_exec("cd ". $dirs['packages'] ."; ".
				"fetch http://www.acme.com/software/mini_httpd/$mini_httpd_version.tar.gz; ".
				"tar zxf $mini_httpd_version.tar.gz");
		_log("fetched and untarred $mini_httpd_version");
	}
	if(!_is_patched($mini_httpd_version)) {
		_exec("cd ". $dirs['packages'] ."/$mini_httpd_version; patch < ". $dirs['patches'] . "/packages/mini_httpd.patch");
		_stamp_package_as_patched($mini_httpd_version);
	}
	_exec("cd ". $dirs['packages'] ."/$mini_httpd_version; make clean; make");

	_log("built minihttpd");
}


$h["build dhcpserver"] = "(re)builds the ISC DHCP server (NOTE: dialog must be confirmed)";
function build_dhcpserver() {
	
	/* TODO: automate compile */
	_prompt("After the screen appears, press TAB and then ENTER. (it's on the TODO list...)", 5);
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
	
	/* TODO: automate compile */
	_prompt("After the screen appears, press TAB and then ENTER. (it's on the TODO list...)", 5);
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
	global $dirs, $wol_version;

	if(!file_exists($dirs['packages'] ."/$wol_version")) {
		_exec("cd ". $dirs['packages'] ."; ".
				"fetch http://heanet.dl.sourceforge.net/sourceforge/ahh/$wol_version.tar.gz; ".
				"tar zxf $wol_version.tar.gz");
		_log("fetched and untarred $wol_version");
	}
	_exec("cd ". $dirs['packages'] ."/$wol_version; ".
			"./configure --disable-nls; ". 
			"make");

	_log("built wol");
}


$h["build ezipupdate"] = "(re)builds and patches ez-ipupdate (dynamic dns update client)";
function build_ezipupdate() {
	global $dirs, $ez_ipupdate_version;
	
	if(!file_exists($dirs['packages'] ."/$ez_ipupdate_version")) {
		_exec("cd ". $dirs['packages'] ."; ".
				"fetch http://dyn.pl/client/UNIX/ez-ipupdate/$ez_ipupdate_version.tar.gz; ".
				"tar zxf $ez_ipupdate_version.tar.gz");
		_log("fetched and untarred $ez_ipupdate_version");
	}
	if(!_is_patched($ez_ipupdate_version)) {
		_exec("cd ". $dirs['packages'] ."/$ez_ipupdate_version; ".
				"patch < ". $dirs['patches'] ."/packages/ez-ipupdate.c.patch");
		_stamp_package_as_patched($ez_ipupdate_version);
	}	
	_exec("cd ". $dirs['packages'] ."/$ez_ipupdate_version; ".
			"./configure; ".
			"make");

	_log("built ez-ipupdate");
}


$h["build bpalogin"] = "(re)builds BPALogin (Big Pond client)";
function build_bpalogin() {
	global $dirs, $bpalogin_version;
	
	if(!file_exists($dirs['packages'] ."/$bpalogin_version")) {
		_exec("cd ". $dirs['packages'] ."; ".
				"fetch http://bpalogin.sourceforge.net/download/$bpalogin_version.tar.gz; ".
				"tar zxf $bpalogin_version.tar.gz");
		_log("fetched and untarred $bpalogin_version");
	}
	_exec("cd ". $dirs['packages'] ."/$bpalogin_version; ".
			"./configure; ".
			"make");

	_log("built bpalogin");
}


$h["build racoon"] = "(re)builds and patches the ipsec-tools version of racoon";
function build_racoon() {
	global $dirs, $ipsec_tools_version;
	
	// TODO: mklibs.pl fails on this because the library has already been added by hand
	// hacked to install lib temporarily

	// TODO: ugly ugly ugly...make clean, make, make clean, make install!!
	
	/* TODO: automate compile */
	_prompt("After the screen appears, press TAB and then ENTER. (it's on the TODO list...)", 5);
	_exec("cd /usr/ports/security/ipsec-tools; patch < ". $dirs['files'] ."/ipsec-tools-makefile.patch");
	_exec("cd /usr/ports/security/ipsec-tools; make clean; make");
	/*_exec("cd /usr/ports/security/ipsec-tools/work/$ipsec_tools_version; ".
			"patch < ". $dirs['patches'] ."/packages/ipsec-tools-0.6.6.patch");*/
	_exec("cd /usr/ports/security/ipsec-tools/work/$ipsec_tools_version; make clean; make install");
	
	_log("built and patched racoon (albeit hackily)");

}


$h["build mpd"] = "(re)builds and patches MPD (Multi-link PPP daemon)";
function build_mpd() {
	global $dirs, $mpd_version;
	
	// TODO: ugly...still need to better judge the port status
	_exec("cd /usr/ports/net/mpd; make clean; make");
	_exec("cd /usr/ports/net/mpd/work/$mpd_version; patch < ". $dirs['patches'] ."/packages/mpd.patch");
	_exec("cd /usr/ports/net/mpd/work/$mpd_version; make");
	
	_log("built and patched MPD");
}

$h["build ataidle"] = "(re)builds ataidle";
function build_ataidle() {
	
	_exec("cd /usr/ports/sysutils/ataidle; make clean; make");
	
	_log("built ataidle");
}


$h["build ucdsnmp"] = "(re)builds and patches UCD-SNMP";
function build_ucdsnmp() {
	global $dirs, $ucd_snmp_version;

	if(!file_exists($dirs['packages'] ."/$ucd_snmp_version.tar.gz")) {
		_exec("cd ". $dirs['packages'] ."; ".
				"fetch http://kent.dl.sourceforge.net/sourceforge/net-snmp/$ucd_snmp_version.tar.gz");
		_log("fetched $ucd_snmp_version");
	}
	if(!file_exists($dirs['packages'] ."/$ucd_snmp_version")) {
		_exec("cd ". $dirs['packages'] ."; tar zxf $ucd_snmp_version.tar.gz");
	}
	if(!_is_patched("$ucd_snmp_version")) {
		_exec("cd ". $dirs['packages'] ."/$ucd_snmp_version; ". 
				"patch < ". $dirs['patches'] ."/packages/ucd-snmp.patch");
		_stamp_package_as_patched("$ucd_snmp_version");
	}

	_prompt("All of the following prompts can all be answered with their default values.", 5);

	_exec("cd ". $dirs['packages'] ."/$ucd_snmp_version; ".
		"./configure  --without-openssl --disable-debugging --enable-static --enable-mini-agent --disable-privacy --disable-testing-code --disable-shared-version --disable-shared --disable-ipv6 '--with-out-transports=TCP Unix' '--with-mib-modules=mibII/interfaces mibII/var_route ucd-snmp/vmstat_freebsd2'");		

	_exec("cd ". $dirs['packages'] ."/$ucd_snmp_version; ". 
			"patch < ". $dirs['files'] ."/ucd-snmp-config.h.patch");

	_exec("cd ". $dirs['packages'] ."/$ucd_snmp_version; make");

	_log("built UCD-SNMP");
}


$h["build siproxd"] = "(re)builds siproxd and installs libosip2 library if not found";
function build_siproxd() {
	
	global $dirs, $siproxd_version;

    if (!file_exists("/usr/local/lib/libosip2.so.3")) {
        _exec("cd /usr/ports/net/libosip2; make clean; make install clean");
        _log("built libosip2 library");
    }

	if(!file_exists($dirs['packages'] ."/$siproxd_version")) {
		_exec("cd ". $dirs['packages'] ."; ".
				"fetch http://downloads.sourceforge.net/siproxd/$siproxd_version.tar.gz;" .
				"tar zxf $siproxd_version.tar.gz; " .
                "patch < ". $dirs['patches'] ."/user/siproxd.patch");
		_log("fetched, untarred and patched $siproxd_version");
	}

	_exec("cd ". $dirs['packages'] ."/$siproxd_version; ".
			"./configure; make");
	
	_log("built siproxd");

}


$h["build tools"] = "(re)builds the little \"helper tools\" that m0n0wall needs (choparp, stats.cgi, minicron, verifysig)";
function build_tools() {
	global $dirs;
	
	_exec("cd ". $dirs['tools'] ."; gcc -o choparp choparp.c");
	_log("built choparp");
	
	_exec("cd ". $dirs['tools'] ."; gcc -o stats.cgi stats.c");
	_log("built stats.cgi");
	
	_exec("cd ". $dirs['tools'] ."; gcc -o minicron minicron.c");
	_log("built minicron");
	
	_exec("cd ". $dirs['tools'] ."; gcc -o verifysig -lcrypto verifysig.c");
	_log("built verifysig");
	
	_exec("cd ". $dirs['tools'] ."; gcc -o wrapresetbtn wrapresetbtn.c");
	_log("built wrapresetbtn");
	
	_exec("cd ". $dirs['tools'] ."; gcc -o voucher -lcrypto -O2 voucher.c");
	_log("built voucher");
}


$h["build bootloader"] = "(re)builds the bootloader files";
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
	build_ataidle();
	build_siproxd();
}

$h["build everything"] = "(re)builds all packages, kernels and the bootloader";
function build_everything() {

	build_syslogd();
	build_clog();
	build_hostapd();
	build_packages();
	build_ports();
	build_tools();
	build_kernels();
	build_bootloader();
}


$h["create"] = "creates the directory structure for the given \"image_name\"";
function create($image_name) {
	global $dirs;
		
	if (file_exists($image_name)) {
		_exec("rm -rf $image_name");
		_exec("rm -rf {$dirs['images']}/*$image_name.img");
		_exec("rm -rf {$dirs['mfsroots']}/*$image_name.gz");
	}
	
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
	global $dirs;

	_exec("perl ". $dirs['minibsd'] ."/mkmini.pl ". $dirs['minibsd'] ."/m0n0wall.files / $image_name");
	
	_log("added base system binaries");
}


$h["populate etc"] = "populates /etc and appropriately links /etc/resolv.conf and /etc/hosts for the given \"image_name\"";
function populate_etc($image_name) {
	global $dirs;
		
	_exec("cp -p ". $dirs['files'] ."/etc/* $image_name/etc/");		// etc stuff not in svn
	_exec("cp -p ". $dirs['etc'] ."/rc* $image_name/etc/");
	_exec("cp ". $dirs['etc'] ."/pubkey.pem $image_name/etc/");
	_log("added etc");
	
	_exec("ln -sf /var/etc/resolv.conf $image_name/etc/resolv.conf");
	_exec("ln -sf /var/etc/hosts $image_name/etc/hosts");
	_log("added resolv.conf and hosts symlinks");
	
}


$h["populate defaultconf"] = "adds the default xml configuration file to the given \"image_name\"";
function populate_defaultconf($image_name) {
	global $dirs;
	
	_exec("cp ". $dirs['phpconf'] ."/config.xml $image_name/conf.default/");
	
	_log("added default config.xml");
}


$h["populate zoneinfo"] = "adds timezone info to the given \"image_name\"";
function populate_zoneinfo($image_name) {
	global $dirs;
	
	_exec("cp ". $dirs['files'] ."/zoneinfo.tgz $image_name/usr/share/");
	
	_log("added zoneinfo.tgz");
}


$h["populate syslogd"] = "adds syslogd to the given \"image_name\"";
function populate_syslogd($image_name) {
	global $dirs;
	
	_exec("cd /usr/src/usr.sbin/syslogd; ".
			"install -s /usr/obj/usr/src/usr.sbin/syslogd/syslogd $image_name/usr/sbin");

	_log("added syslogd");
}


$h["populate clog"] = "adds circular logging to the given \"image_name\"";
function populate_clog($image_name) {
	global $dirs;
	
	_exec("cd /usr/src/usr.sbin/clog; ".
			"install -s /usr/obj/usr/src/usr.sbin/clog/clog $image_name/usr/sbin");

	_log("added clog");
}


$h["populate php"] = "adds the php interpreter to the given \"image_name\"";
function populate_php($image_name) {
	global $dirs, $php_version;
	
	_exec("cd ". $dirs['packages'] ."/$php_version/; install -s sapi/cgi/php $image_name/usr/local/bin");
	_exec("cp ". $dirs['files'] ."/php.ini $image_name/usr/local/lib/");

	_log("added php");
}


$h["populate minihttpd"] = "adds the mini-httpd server to the given \"image_name\"";
function populate_minihttpd($image_name) {
	global $dirs, $mini_httpd_version;
	
	_exec("cd ". $dirs['packages'] ."/$mini_httpd_version; ".
			"install -s mini_httpd $image_name/usr/local/sbin");
	
	_log("added mini_httpd");
}


$h["populate dhclient"] = "adds the ISC DHCP client to the given \"image_name\"";
function populate_dhclient($image_name) {
	global $dirs;
	
	_exec("cp /sbin/dhclient $image_name/sbin/");
	_exec("cp ". $dirs['tools'] ."/dhclient-script $image_name/sbin/");
	_exec("chmod a+rx $image_name/sbin/dhclient-script");
	
	_log("added dhclient");
}


$h["populate dhcpserver"] = "adds the ISC DHCP server to the given \"image_name\"";
function populate_dhcpserver($image_name) {
	global $dirs;
	
	_exec("cd /usr/ports/net/isc-dhcp3-server; ".
		"install -s work/dhcp-*/work.freebsd/server/dhcpd $image_name/usr/local/sbin");
	
	_log("added dhcp server");
}


$h["populate dhcprelay"] = "adds the ISC DHCP relay to the given \"image_name\"";
function populate_dhcprelay($image_name) {
	global $dirs;
	
	_exec("cd /usr/ports/net/isc-dhcp3-relay; ".
		"install -s work/dhcp-*/work.freebsd/relay/dhcrelay $image_name/usr/local/sbin");
	
	_log("added dhcp relay");
}


$h["populate dnsmasq"] = "adds Dnsmasq (DNS forwarder) to the given \"image_name\"";
function populate_dnsmasq($image_name) {
	global $dirs;
	
	_exec("cd /usr/ports/dns/dnsmasq; ".
		"install -s work/dnsmasq-*/src/dnsmasq $image_name/usr/local/sbin");
	
	_log("added dnsmasq");
}


$h["populate msntp"] = "adds msntp (NTP client) to the given \"image_name\"";
function populate_msntp($image_name) {
	global $dirs;
	
	_exec("cd /usr/ports/net/msntp; ".
		"install -s work/msntp-*/msntp $image_name/usr/local/bin");
	
	_log("added msntp");
}


$h["populate wol"] = "adds wol (wake on lan client) to the given \"image_name\"";
function populate_wol($image_name) {
	global $dirs, $wol_version;
	
	_exec("cd ". $dirs['packages'] ."/$wol_version; ".
		"install -s src/wol $image_name/usr/local/bin");
	
	_log("added wol");
}


$h["populate ezipupdate"] = "adds ez-ipupdate (dynamic dns client) to the given \"image_name\"";
function populate_ezipupdate($image_name) {
	global $dirs, $ez_ipupdate_version;
	
	_exec("cd ". $dirs['packages'] ."/$ez_ipupdate_version; ".
		"install -s ez-ipupdate $image_name/usr/local/bin");
	
	_log("added ez-ipupdate");
}


$h["populate bpalogin"] = "adds bpalogin (Big Pond client) to the given \"image_name\"";
function populate_bpalogin($image_name) {
	global $dirs, $bpalogin_version;
	
	_exec("cd ". $dirs['packages'] ."/$bpalogin_version; ".
		"install -s bpalogin $image_name/usr/local/sbin");

	_log("added bpalogin");
}


$h["populate mpd"] = "adds MPD (Multi-link PPP daemon) to the given \"image_name\"";
function populate_mpd($image_name) {
	global $dirs;
	
	_exec("cd /usr/ports/net/mpd; install -s work/mpd-*/src/mpd $image_name/usr/local/sbin");
	
	_log("added mpd");
}


$h["populate racoon"] = "adds racoon to the given \"image_name\"";
function populate_racoon($image_name) {
	global $dirs, $ipsec_tools_version;
	
	_exec("cd /usr/ports/security/ipsec-tools; ".
		"install -s work/$ipsec_tools_version/src/racoon/.libs/racoon $image_name/usr/local/sbin; ".
		"install -s work/$ipsec_tools_version/src/libipsec/.libs/libipsec.so.0 $image_name/usr/local/lib");
	_exec("cp /usr/ports/security/ipsec-tools/work/$ipsec_tools_version/src/setkey/setkey $image_name/usr/local/sbin/");
	
	_log("added racoon");
}


$h["populate ucdsnmp"] = "adds UCD-SNMP to the given \"image_name\"";
function populate_ucdsnmp($image_name) {
	global $dirs, $ucd_snmp_version;
	
	_exec("cd ". $dirs['packages'] ."/$ucd_snmp_version; ".
		"install -s agent/snmpd $image_name/usr/local/sbin");
	
	_log("added ucd-snmp");
}

$h["populate siproxd"] = "adds the siproxd to the given \"image_name\"";
function populate_siproxd($image_name) {
	global $dirs, $siproxd_version;
	
	_exec("cd ". $dirs['packages'] ."/$siproxd_version; ".
			"install -s src/siproxd $image_name/usr/local/sbin");
	
	_log("added siprxod");
}


$h["populate tools"] = "adds the m0n0wall \"helper tools\" to the given \"image_name\"";
function populate_tools($image_name) {
	global $dirs;
	
	_exec("cd ". $dirs['tools'] ."; ".
		"install -s choparp $image_name/usr/local/sbin; ".
		"install -s stats.cgi $image_name/usr/local/www; ".
		"install -s minicron $image_name/usr/local/bin; ".
		"install -s verifysig $image_name/usr/local/bin; ".
		"install runmsntp.sh $image_name/usr/local/bin; ".
		"install wrapresetbtn $image_name/usr/local/sbin; ".
		"install -s voucher $image_name/usr/local/bin; ".
		"install ppp-linkup vpn-linkdown vpn-linkup $image_name/usr/local/sbin");
}


$h["populate phpconf"] = "adds the php configuration system to the given \"image_name\"";
function populate_phpconf($image_name) {
	global $dirs;

	_exec("cp ". $dirs['phpconf'] ."/rc* $image_name/etc/");
	_exec("cp ". $dirs['phpconf'] ."/inc/* $image_name/etc/inc/");
	
	_log("added php conf scripts");
}


$h["populate webgui"] = "adds the php webgui files to the given \"image_name\"";
function populate_webgui($image_name) {
	global $dirs;
	
	_exec("cp ". $dirs['webgui'] ."/* $image_name/usr/local/www/");
	
	_log("added webgui");
}


$h["populate captiveportal"] = "adds the captiveportal scripts to the given \"image_name\"";
function populate_captiveportal($image_name) {
	global $dirs;
	
	_exec("cp ". $dirs['captiveportal'] ."/* $image_name/usr/local/captiveportal/");
	
	_log("added captiveportal");
}


$h["populate libs"] = "adds the required libraries (using mklibs.pl) to the given \"image_name\"";
function populate_libs($image_name) {
	global $dirs;
	
	_exec("perl ". $dirs['minibsd'] ."/mklibs.pl $image_name > tmp.libs");
	_exec("perl ". $dirs['minibsd'] ."/mkmini.pl tmp.libs / $image_name");
	_exec("rm tmp.libs");
	
	_log("added libraries");	
}

$h["populate ataidle"] = "adds ataidle to the given \"image_name\"";
function populate_ataidle($image_name) {
	
	_exec("cd /usr/ports/sysutils/ataidle/work/ataidle-1.0/; ".
		"install -s ataidle $image_name/usr/local/sbin");
	
	_log("added ataidle");
}

$h["populate everything"] = "adds all packages, scripts and config files to the given \"image_name\"";
function populate_everything($image_name) {
	
	populate_base($image_name);
	populate_etc($image_name);
	populate_defaultconf($image_name);
	populate_zoneinfo($image_name);
	populate_syslogd($image_name);
	populate_clog($image_name);
	populate_php($image_name);
	populate_minihttpd($image_name);
	populate_msntp($image_name);
	populate_ataidle($image_name);
	populate_bpalogin($image_name);
	populate_dhclient($image_name);
	populate_dhcprelay($image_name);
	populate_dhcpserver($image_name);
	populate_dnsmasq($image_name);
	populate_ezipupdate($image_name);
	populate_mpd($image_name);
	populate_racoon($image_name);
	populate_ucdsnmp($image_name);
	populate_wol($image_name);
	populate_siproxd($image_name);
	populate_tools($image_name);
	populate_phpconf($image_name);
	populate_webgui($image_name);
	populate_captiveportal($image_name);
	populate_libs($image_name);
}

// TODO: this is quite large and ugly
$h["package"] = "package the specified image directory into an .img for the specified platform  (i.e. package generic-pc testimage)";
function package($platform, $image_name) {
	global $dirs;
	global $mfsroot_pad, $image_pad;
	
	_set_permissions($image_name);
	
	if(!file_exists("tmp")) {
		mkdir("tmp");
		mkdir("tmp/mnt");
		mkdir("tmp/stage");
	}
	
	$kernel = _platform_to_kernel($platform);
	
	// mfsroot

	// add rootfs
	_exec("cd tmp/stage; tar -cf - -C $image_name ./ | tar -xpf -");

	// ...system modules		
	_exec("mkdir tmp/stage/boot");
	_exec("mkdir tmp/stage/boot/kernel");
	if ($platform == "generic-pc" || 
		$platform == "generic-pc-cdrom") {
		_exec("cp /sys/i386/compile/$kernel/modules/usr/src/sys/modules/acpi/acpi/acpi.ko tmp/stage/boot/kernel/");
	}
	
	// ...stamps
	_exec("echo \"". basename($image_name) ."\" > tmp/stage/etc/version");
	_exec("echo `date` > tmp/stage/etc/version.buildtime");
	_exec("echo $platform > tmp/stage/etc/platform");
	
	// get size and package mfsroot
	$mfsroot_size = _get_dir_size("tmp/stage") + $mfsroot_pad;
	
	_exec("dd if=/dev/zero of=tmp/mfsroot bs=1k count=$mfsroot_size");
	_exec("mdconfig -a -t vnode -f tmp/mfsroot -u 0");

	_exec("bsdlabel -rw md0 auto");
	_exec("newfs -O 1 -b 8192 -f 1024 -o space -m 0 /dev/md0c");

	_exec("mount /dev/md0c tmp/mnt");
	_exec("cd tmp/mnt; tar -cf - -C ../stage ./ | tar -xpf -");

    // dummynet.ko and ipfw.ko reside in mfsroot/boot/kernel
	_exec("mkdir -p tmp/mnt/boot/kernel");
	_exec("cp /sys/i386/compile/$kernel/modules/usr/src/sys/modules/dummynet/dummynet.ko tmp/mnt/boot/kernel/");
	_exec("cp /sys/i386/compile/$kernel/modules/usr/src/sys/modules/ipfw/ipfw.ko tmp/mnt/boot/kernel/");
	
	_log("---- $platform - " . basename($image_name) . " - mfsroot ----");
	_exec("df tmp/mnt");

	_exec("umount tmp/mnt");
	_exec("rm -rf tmp/stage/*");
	_exec("mdconfig -d -u 0");
	_exec("gzip -9 tmp/mfsroot");
	_exec("mv tmp/mfsroot.gz {$dirs['mfsroots']}/$platform-". basename($image_name) .".gz");
	


	// .img
	if ($platform != "generic-pc-cdrom") {
		
		// add mfsroot
		_exec("cp {$dirs['mfsroots']}/$platform-". basename($image_name) .".gz ".
			"tmp/stage/mfsroot.gz");
		
		// ...boot
		_exec("mkdir tmp/stage/boot");
		_exec("mkdir tmp/stage/boot/kernel");
	    _exec("cp /usr/obj/usr/src/sys/boot/i386/loader/loader tmp/stage/boot/");
		_exec("cp {$dirs['boot']}/$platform/loader.rc tmp/stage/boot/");
	
		// ...conf
		_exec("mkdir tmp/stage/conf");
		_exec("cp {$dirs['phpconf']}/config.xml tmp/stage/conf");
		_exec("cp /sys/i386/compile/$kernel/kernel.gz tmp/stage/kernel.gz");
		
		// get size and populate
		$image_size = _get_dir_size("tmp/stage") + $asterisk_size + $image_pad;
		$image_size += 16 - ($image_size % 16);
		
		_exec("dd if=/dev/zero of=tmp/image.bin bs=1k count=$image_size");			
		_exec("mdconfig -a -t vnode -f tmp/image.bin -u 0");
		_exec("bsdlabel -Brw -b /usr/obj/usr/src/sys/boot/i386/boot2/boot md0 auto");
		_exec("newfs -O 1 -b 8192 -f 1024 -o space -m 0 /dev/md0a");
		
		_exec("mount /dev/md0a tmp/mnt");
		_exec("cd tmp/mnt; tar -cf - -C ../stage ./ | tar -xpf -");
		_log("---- $platform - " . basename($image_name) . " - system partition ----");
		_exec("df tmp/mnt");
		_exec("umount tmp/mnt");
		
		// cleanup
		_exec("mdconfig -d -u 0");
		_exec("gzip -9 tmp/image.bin");
		_exec("mv tmp/image.bin.gz {$dirs['images']}/m0n0wall-$platform-". basename($image_name) .".img");
		
	// .iso
	} else if($platform == "generic-pc-cdrom" && !file_exists($dirs['images'] ."/$platform-$version-". basename($image_name) .".iso")) {

		_exec("mkdir tmp/cdroot");
		_exec("cp ". $dirs['mfsroots'] ."/$platform-". basename($image_name) .".gz tmp/cdroot/mfsroot.gz");
		_exec("cp /sys/i386/compile/$kernel/kernel.gz tmp/cdroot/kernel.gz");		

		_exec("mkdir tmp/cdroot/boot");
	    _exec("cp /usr/obj/usr/src/sys/boot/i386/cdboot/cdboot tmp/cdroot/boot/");		
	    _exec("cp /usr/obj/usr/src/sys/boot/i386/loader/loader tmp/cdroot/boot/");
		_exec("cp ". $dirs['boot'] ."/$platform/loader.rc tmp/cdroot/boot/");
		_exec("cp /usr/obj/usr/src/sys/boot/i386/boot2/boot tmp/cdroot/boot/");

		_exec("mkisofs -b \"boot/cdboot\" -no-emul-boot -A \"m0n0wall CD-ROM image\" ".
			"-c \"boot/boot.catalog\" -d -r -publisher \"m0n0.ch\" ".
			"-p \"Your Name\" -V \"m0n0wall_cd\" -o \"m0n0wall.iso\" tmp/cdroot/");
			
		_exec("mv m0n0wall.iso ". $dirs['images'] ."/m0n0wall-cdrom-". basename($image_name) .".iso");
	}
	
	_exec("rm -rf tmp");
}


function _set_permissions($image_name) {
	
	_exec("chmod 755 $image_name/etc/rc*");
	_exec("chmod 644 $image_name/etc/pubkey.pem");
	
	_exec("chmod 644 $image_name/etc/inc/*");
	
	_exec("chmod 644 $image_name/conf.default/config.xml");

	_exec("chmod 644 $image_name/usr/local/www/*");
	_exec("chmod 755 $image_name/usr/local/www/*.php");
	_exec("chmod 755 $image_name/usr/local/www/*.cgi");
	
	_exec("chmod 644 $image_name/usr/local/captiveportal/*");
	_exec("chmod 755 $image_name/usr/local/captiveportal/*.php");
	
	_log("permissions set.");
}



function _stamp_package_as_patched($package_version) {
	global $dirs;
	
	touch($dirs['packages'] ."/$package_version/$package_version.patched");
	
	_log("patched $package_version");
}

function _is_patched($package_version) {
	global $dirs;
	
	return(file_exists($dirs['packages'] ."/$package_version/$package_version.patched"));
}


function _platform_to_kernel($platform) {
	global $platforms;
	
	if($platform == "generic-pc-cdrom" || $platform == "generic-pc") {
		$kernel = "M0N0WALL_GENERIC";
	} else if($platform == "generic-pc-smp") {
		$kernel = "M0N0WALL_GENERIC_SMP";
	} else if($platform == "wrap") {
		$kernel = "M0N0WALL_WRAPALIX";
	} else {
		$kernel = "M0N0WALL_" . strtoupper($platform);
	}

	return $kernel;
}


function _exec($cmd) {
	$ret = 0;
	_log($cmd);
	passthru($cmd, $ret);
	if($ret != 0) {
		_log("COMMAND FAILED: $cmd");
		exit(1);
	}
}


function _log($msg) {
	print "$msg\n";
}


function _get_dir_size($dir) {
	exec("du -d 0 $dir", $out);
	$out = preg_split("/\s+/", $out[0]);
	return $out[0];
}


function _prompt($msg, $duration=0) {
	
	$msg = wordwrap(" - $msg", 74, "\n - ");
	if($duration) {
		print "--[ Attention! ]-------------------------------------------------------------\n\n";
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


function _usage() {
	
	print "\n";
	print "./m0n0dev.php new image_name             start a new image\n";
	print "./m0n0dev.php patch something            patch a target\n";
	print "./m0n0dev.php build something            build a target\n";
	print "./m0n0dev.php parsecheck                 check for stupid mistakes\n";
	print "./m0n0dev.php populate something image   populate an image with a target\n";
	print "./m0n0dev.php package platform image     package image for specified platform\n";
	
	print "\nHelp is available by prefixing the command with \"help\" (i.e. help patch)\n\n";
	
	exit(1);
}


// DONE by rOger Eisenecher: I could generate these...
$functions = get_defined_functions();
sort($functions["user"]);
foreach ($functions["user"] as $func) {
	$parts = explode('_', $func, 2);
	$group = $parts[0];
	$f = $parts[1];
	$funcs["$group"][] = $f;
}

$h["patch"] = "available patch options: " . implode(", ", $funcs["patch"]);
$h["build"] = "available build options: " . implode(", ", $funcs["build"]);
$h["populate"] = "available populate options: " . implode(", ", $funcs["populate"]);

// --[ command line parsing ]--------------------------------------------------

// nothing to do, here's what's possible
if($argc == 1) {
	_usage();

// here's some help if it's available
} else if($argv[1] == "help") {
	// not enough arguments
	if($argc == 2) {
		_log("Not enough arguments provided for help");
	}
	// form a command name and see if it's in the help array
	$c = implode(" ", array_slice($argv, 2));
	array_key_exists($c, $h) ? 
		_prompt($h[$c]) : 
		_log("no help available on ($c)! :(");;

} else if ($argv[1] == "new") {
	
	$image_name = "{$dirs['images']}/" . rtrim($argv[2], "/");
	create($image_name);
	populate_everything($image_name);


// patch functions are all defined with no arguments
} else if($argv[1] == "patch") {
	$f = implode("_", array_slice($argv, 1));
	function_exists($f) ?
		$f() :
		_log("Invalid patch command!");		

// build functions are all defined with no arguments except for "build_kernel"
} else if($argv[1] == "build") {
	if($argv[2] == "kernel") {
		build_kernel($argv[3]);
	} else {
		$f = implode("_", array_slice($argv, 1));
		function_exists($f) ?
			$f() :
			_log("Invalid build command!");
	}

// populate functions are all defined with a single argument:
// (image_name directory)
} else if($argv[1] == "populate") {
	// make a function name out of the arguments
	$f = implode("_", array_slice($argv, 1, 2));
	// not a valid function, show usage
	if(!function_exists($f)) {
		_log("Invalid populate command!");
	}
	// construct an absolute path to the image
	$image_name = $dirs['images']. "/" . rtrim($argv[3], "/");
	// not a valid image, show usage
	if(!file_exists($image_name)) {
		_log("Image does not exist!");
	}
	$f($image_name);


// the package function is defined with two arguments:
// (platform, image_name)
} else if($argv[1] == "package") {
	// construct an absolute path to the image
	$image_name = $dirs['images']. "/" . rtrim($argv[3], "/");
	// not a valid image, show usage
	if(!file_exists($image_name)) {
		_log("Image does not exist!");
	}
	// we're packaging all platforms go right ahead
	if($argv[2] == "all") {
		foreach($platforms as $platform) {
			package($platform, $image_name);			
		}
	// check the specific platform before attempting to package
	} else if(in_array($argv[2], $platforms)) {
		package($argv[2], $image_name);
	// not a valid package command...
	} else {
		_log("Invalid packaging command!");
	}

} else if ($argv[1] == "parsecheck") {

	passthru("find {$dirs['webgui']}/ -type f -name \"*.php\" -exec php -l {} \; -print | grep Parse");
	passthru("find {$dirs['webgui']}/ -type f -name \"*.inc\" -exec php -l {} \; -print | grep Parse");
	passthru("find {$dirs['phpconf']}/ -type f -name \"*rc.*\" -exec php -l {} \; -print | grep Parse");
	passthru("find {$dirs['phpconf']}/ -type f -name \"*.inc\" -exec php -l {} \; -print | grep Parse");

// hmmm, don't have any verbs like that!
} else {
	_log("Huh?");
	exit(1);
}

exit();

?>
