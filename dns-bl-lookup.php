#!/usr/bin/php
<?php

/* 
  version: 1                
  date: 01.06.2016 
  Author: Tomasz@Oleksiewicz.pl 
  Licence: GNU                                   
  Copyright (C) 1999-2016 Tomasz@Oleksiewicz.pl  

  This program is distributed in the hope that it will be useful, 
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.


*/




$start_time = time();

define ( 'PAUSE', 25 ); // seconds to start next ip check 
define ( 'DEBUG', TRUE ); // additional output
define ( 'PING', TRUE ); // check if hosts are up 

$ping_list = array ('icmp', 25, 80, 143, 81, 8080, ); // port list to check if host is up 
$ping_timeout = 1; // seconds

$dnsbl_list = array (
  '0spam.fusionzero.com', 'access.redhawk.org', 'all.rbl.jp', 'all.s5h.net', 'all.spamrats.com', 'aspews.ext.sorbs.net', 'b.barracudacentral.org', 'backscatter.spameatingmonkey.net', 'bad.psky.me', 'bb.barracudacentral.org', 
  /* 'bhnc.njabl.org', */
  'bl.blocklist.de', 'bl.drmx.org', 'bl.emailbasura.org', 'bl.konstant.no', 'bl.mailspike.net', 'bl.mav.com.br', 'bl.nosolicitado.org', 'bl.nszones.com', 'bl.scientificspam.net', 'bl.score.senderscore.com', 'bl.spamcannibal.org', 'bl.spamcop.net', 'bl.spameatingmonkey.net', 'bl.suomispam.net', 
  /* 'bl.tiopan.com', */
  'black.junkemailfilter.com', 'blackholes.five-ten-sg.com', 
  /* 'blackholes.intersil.net', */
  'blackholes.wirehub.net', 'blacklist.sci.kun.nl', 'blacklist.woody.ch', 'block.dnsbl.sorbs.net', 'blocked.hilli.dk', 'bogons.cymru.com', 'bsb.empty.us', 'bsb.spamlookup.net', 'cart00ney.surriel.com', 'cbl.abuseat.org', 'cbl.anti-spam.org.cn', 'cblless.anti-spam.org.cn', 'cblplus.anti-spam.org.cn', 'cdl.anti-spam.org.cn', 'cidr.bl.mcafee.com', 'combined.abuse.ch', 
  /* 'combined.njabl.org', */ 
  'combined.rbl.msrbl.net', 'db.wpbl.info', 'dev.null.dk', 'dialup.blacklist.jippg.org', 'dialups.mail-abuse.org', 'dialups.visi.com', 'dnsbl-0.uceprotect.net', 'dnsbl-1.uceprotect.net', 'dnsbl-2.uceprotect.net', 'dnsbl-3.uceprotect.net', 'dnsbl.abuse.ch', 'dnsbl.anticaptcha.net', 'dnsbl.antispam.or.id', 'dnsbl.aspnet.hu', 'dnsbl.cobion.com', 'dnsbl.dronebl.org', 'dnsbl.inps.de', 'dnsbl.justspam.org', 'dnsbl.kempt.net', 'dnsbl.mags.net', 'dnsbl.net.ua', 
  /* 'dnsbl.njabl.org', */
  /* 'dnsbl.proxybl.org', */
  'dnsbl.rangers.eu.org', 'dnsbl.rv-soft.info', 'dnsbl.rymsho.ru', 'dnsbl.sorbs.net', 
  /* 'dnsbl.spam-champuru.livedoor.com', */
  'dnsbl.tornevall.org', 'dnsbl.webequipped.com', 'dnsbl.zapbl.net', 'dnsrbl.org', 'dnsrbl.swinog.ch', 'drone.abuse.ch', 'duinv.aupads.org', 'dul.dnsbl.sorbs.net', 'dul.pacifier.net', 'dul.ru', 'dyn.nszones.com', 'dyna.spamrats.com', 'escalations.dnsbl.sorbs.net', 'exitnodes.tor.dnsbl.sectoor.de', 'fnrbl.fast.net', 'forbidden.icm.edu.pl', 'hil.habeas.com', 'hostkarma.junkemailfilter.com', 'http.dnsbl.sorbs.net', 'httpbl.abuse.ch', 'images.rbl.msrbl.net', 'intruders.docs.uu.se', 'ipbl.zeustracker.abuse.ch', 'ips.backscatterer.org', 'ix.dnsbl.manitu.net', 'korea.services.net', 'l1.bbfh.ext.sorbs.net', 
  /* 'l2.apews.org', */
  'l2.bbfh.ext.sorbs.net', 'l3.bbfh.ext.sorbs.net', 'l4.bbfh.ext.sorbs.net', 'list.bbfh.org', 'list.blogspambl.com', 'list.quorum.to', 'lookup.dnsbl.iip.lu', 'mail-abuse.blacklist.jippg.org', 'misc.dnsbl.sorbs.net', 'msgid.bl.gweep.ca', 'multi.surbl.org', 'netbl.spameatingmonkey.net', 'netscan.rbl.blockedservers.com', 'new.dnsbl.sorbs.net', 'new.spam.dnsbl.sorbs.net', 'no-more-funn.moensted.dk', 'noptr.spamrats.com', 'old.dnsbl.sorbs.net', 'old.spam.dnsbl.sorbs.net', 'opm.tornevall.org', 'orvedb.aupads.org', 'pbl.spamhaus.org', 'phishing.rbl.msrbl.net', 'pofon.foobar.hu', 'problems.dnsbl.sorbs.net', 'projecthoneypot.org', 'proxies.dnsbl.sorbs.net', 'proxy.bl.gweep.ca', 'psbl.surriel.com', 'pss.spambusters.org.ar', 'rbl.abuse.ro', 'rbl.blockedservers.com', 'rbl.dns-servicios.com', 'rbl.efnet.org', 'rbl.efnetrbl.org', 'rbl.interserver.net', 'rbl.iprange.net', 'rbl.lugh.ch', 'rbl.megarbl.net', 'rbl.orbitrbl.com', 'rbl.polarcomm.net', 
  /* 'rbl.rbldns.ru', */
  'rbl.schulte.org', 'rbl.scrolloutf1.com', 'rbl.snark.net', 'rbl.talkactive.net', 'rbl2.triumf.ca', 'recent.dnsbl.sorbs.net', 'recent.spam.dnsbl.sorbs.net', 'relays.bl.gweep.ca', 'relays.bl.kundenserver.de', 'relays.dnsbl.sorbs.net', 
  /* 'relays.mail-abuse.org', */
  'relays.nether.net', 'rep.mailspike.net', 'rsbl.aupads.org', 'safe.dnsbl.sorbs.net', 'sbl-xbl.spamhaus.org', 'sbl.nszones.com', 'sbl.spamhaus.org', 'short.rbl.jp', 'singular.ttk.pte.hu', 'smtp.dnsbl.sorbs.net', 'socks.dnsbl.sorbs.net', 'spam.abuse.ch', 'spam.dnsbl.anonmails.de', 'spam.dnsbl.sorbs.net', 'spam.olsentech.net', 'spam.pedantic.org', 'spam.rbl.blockedservers.com', 'spam.rbl.msrbl.net', 'spam.spamrats.com', 'spamguard.leadmon.net', 'spamlist.or.kr', 'spamrbl.imp.ch', 'spamsources.fabel.dk', 'srn.surgate.net', 'st.technovision.dk', 't1.dnsbl.net.au', 'tor.dan.me.uk', 'tor.dnsbl.sectoor.de', 'tor.efnet.org', 'torexit.dan.me.uk', 'truncate.gbudb.net', 'ubl.unsubscore.com', 'virbl.dnsbl.bit.nl', 'virus.rbl.jp', 'virus.rbl.msrbl.net', 'vote.drbl.caravan.ru', 'vote.drbl.gremlin.ru', 'web.dnsbl.sorbs.net', 'web.rbl.msrbl.net', 'work.drbl.caravan.ru', 'work.drbl.gremlin.ru', 'wormrbl.imp.ch', 'xbl.spamhaus.org', 'z.mailspike.net', 'zen.spamhaus.org', 'zombie.dnsbl.sorbs.net',

);


$ip_list = array( // your ip's  
  // some pool
//  array ( 'from' => '1.2.3.1',    'to' => '1.2.3.254'  ),
  // TEST IP (bad host)
  '186.190.224.45', 

);


/* Main loop   */
$listed = array();
$l = FALSE;
foreach ( $ip_list as $ip_item ) {
  if ( is_array ( $ip_item ) ) {
    $ips = enumerate_ips( $ip_item );
    foreach ( $ips as $ip ) {
	if ($l === FALSE) $wait = 0; else { $wait = wait( PAUSE ); if (DEBUG) echo "DEBUG: wait $wait sec (".PAUSE." sec)\n"; }
      $l = lookup ( $ip ); 
	  if (is_array($l)) foreach ($l as $m) $listed[] = $m;
    }
  }
  else {
	if ($l === FALSE) $wait = 0; else { $wait = wait ( PAUSE ); if (DEBUG) echo "DEBUG: wait $wait sec (".PAUSE." sec)\n"; } 
    $l = lookup ( $ip_item );
	if (is_array($l)) foreach ($l as $m) $listed[] = $m;
  }
}
/* Output results */
if (count($listed)) {
  $results_ip = array();
  $results_dnsbl = array();
  echo "START BLACKLISTED IP'S\n";
  foreach ($listed as $list_item) {
    list ($ip, $dnsbl, $records) = $list_item;
	$results_ip[$ip][$dnsbl] = $records;
	$results_dnsbl[$dnsbl][$ip] = $records;
    //echo "$ip listed $dnsbl - " . $records[0]['ip'] . ', ttl: ' . $records[0]['ttl'] . "\n" ;
  }
  echo 'IP listed: ' . count($results_ip) . "\n";
  foreach ($results_ip as $ip => $dnsbl_list) {
	echo "  $ip (" . count ($dnsbl_list) . " dnsbl's)\n"; 
  }
  echo 'Dnsbl listed: ' . count($results_dnsbl) . "\n";
  foreach ($results_dnsbl as $dnsbl => $ip_list) {
	echo "  $dnsbl (" . count ($ip_list) . " ip's)\n";
  }  
  echo "Details by IP\n";
  foreach ($results_ip as $ip => $dnsbl_list) {
	echo "  $ip - " . count ($dnsbl_list) . "\n";
	foreach ($dnsbl_list as $dnsbl => $records) {
	  echo "    $ip - $dnsbl - " . $records[0]['ip'] . ', ttl: ' . $records[0]['ttl'] . "\n" ;
	}
  }
  echo "Details by dnsbl\n";
  foreach ($results_dnsbl as $dnsbl => $ip_list) {
	echo "  $dnsbl - " . count ($ip_list) . "\n";
	foreach ($ip_list as $ip => $records) {
	  echo "    $ip - $dnsbl - " . $records[0]['ip'] . ', ttl: ' . $records[0]['ttl'] . "\n" ;
	}
  }
  
  echo "END\n";
  $end_time = time();
  //echo 'Listed: ' . count ($listed) . "\n";
  echo 'Execution time: ' . format_time($end_time - $start_time) . "sec\n";
}















/* Functions */

function format_time ($sec) {
	$ret = '';
	$days = floor($sec / 86400);
	if ($days) $ret .= "$days days ";
    $hours = floor(($sec - $days * 86400) / 3600);
    $minutes = floor(($sec - $days * 86400 - $hours * 3600) / 60);
    $seconds = floor($sec - $days * 86400 - $hours * 3600 - $minutes * 60);
	$ret .= sprintf('%02d:%02d:%02d', $hours, $minutes, $seconds);
	return $ret;
}

function lookup ( $ip ) {
	global $dnsbl_list;
	$ret = array();
	if (filter_var($ip, FILTER_VALIDATE_IP)) {
		if (PING && !is_up($ip)) {
			if (DEBUG) echo "DEBUG: $ip looks not up. Skipping...\n";	
			return FALSE;
		}
		else {
			$reverse_ip = implode('.', array_reverse(explode('.', $ip)));
			foreach($dnsbl_list as $dnsbl) {
				
				$records = dns_get_record( $reverse_ip . '.' . $dnsbl . '.', DNS_A );	

				if ( $records !== FALSE && count($records) ) {     
					if (DEBUG) echo "DEBUG: $ip, dnsbl: $dnsbl - listed: ". serialize($records) ."\n";
					$ret[] = array($ip, $dnsbl, $records);  
				} 
				elseif ( $records === FALSE ) {
					if (DEBUG) echo "DEBUF: $ip, dnsbl: $dnsbl - FALSE returned (?)\n";
				}
				else { // count 0
					if (DEBUG) echo "DEBUG: $ip, dnsbl: $dnsbl - not listed\n";  
				}
			}
		}
	}
	else {
		fwrite(STDERR, "WORNING: Wrong IP: $ip\n");
	}
	return $ret;
}


function enumerate_ips ( $ip_item ) {
  $ret = array();
  if ( isset($ip_item['from']) && isset($ip_item['to']) &&
       filter_var($ip_item['from'], FILTER_VALIDATE_IP) &&
       filter_var($ip_item['to'], FILTER_VALIDATE_IP) ) {
    $from = ip2long($ip_item['from']);
    $to   = ip2long($ip_item['to']);
    for ($i = $from; $i <= $to; $i++) {
      $ret[] = long2ip($i);
    }
    if ($from > $to) {
      fwrite(STDERR, 'WORNING: Wrong from - to order on $ip_list:' . str_replace("\n", "", var_export($ip_item)) . "\n");
    }    
  }
  else {
    fwrite(STDERR, 'WORNING: Wrong $ip_list configuration:' . str_replace("\n", "", var_export($ip_item)) . "\n");
  }
  return $ret;
}

function wait($wait, $before = FALSE) {
	/* 
		Wait $wait seconds from last wait_to execution end but no wait if time is already out.
        If $before is given, use it instead end of last wait execution. 	
        On first execution ($last_end = null) if $before === NULL, waiting $time seconds. 
		If $before === FALSE on firest executio, no wait.	
	*/
	static $last_end = NULL;
	$w = 0;
	if ($before !== NULL && $before !== FALSE) {
		$last_end = $before;
	}
	if ($last_end === NULL && $before === FALSE ) {
		// do not wait
	}
	else {
	    if($last_end === NULL) {
			$last_end = time();
		}
		$w = $last_end + $wait - time(); 		
		if ($w > 0) sleep($w); else $w = 0;
	}
	$last_end = time();
	return $w;
}

function is_up($ip, $timeout = null) {
	global $ping_list, $ping_timeout;
	if ($timeout === null) $timeout = $ping_timeout;
	foreach ($ping_list as $port) {
		if ($port == 'icmp') {
			exec ("ping -c 1 -W $timeout $ip", $res, $retval);
			if ($retval === 0) return TRUE;
		}
		else {
			$fsock = @fsockopen($ip, $port, $errno, $errstr, $timeout);
			if ($fsock !== FALSE) {
				fclose($fsock);
				return TRUE;
			}
		}
	}
	return FALSE;
}

