// PAC (Proxy Auto Configuration) Filter from EasyList rules
// 
// Copyright (C) 2017 by Steven T. Smith <steve dot t dot smith at gmail dot com>, GPL
// https://github.com/essandess/easylist-pac-privoxy/
//
// PAC file created on Fri, 31 May 2019 18:21:11 GMT
// Created with command: test-easylist_pac -d /scripts/github/proxy/ -b 1.1.1.1:53
//
// http://www.gnu.org/licenses/lgpl.txt
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// If you normally use a proxy, replace "DIRECT" below with
// "PROXY MACHINE:PORT"
// where MACHINE is the IP address or host name of your proxy
// server and PORT is the port number of your proxy server.
//
// Influenced in part by code from King of the PAC from http://securemecca.com/pac.html

// Define the blackhole proxy for blocked adware and trackware

var normal = "DIRECT";
var proxy = "DIRECT";                  // e.g. 127.0.0.1:3128
// var blackhole_ip_port = "127.0.0.1:8119";  // ngnix-hosted blackhole
// var blackhole_ip_port = "8.8.8.8:53";      // GOOG DNS blackhole; do not use: no longer works with iOS 11—causes long waits on some sites
var blackhole_ip_port = "1.1.1.1:53";    // on iOS a working blackhole requires return code 200;
// e.g. use the adblock2privoxy nginx server as a blackhole
var blackhole = "PROXY " + blackhole_ip_port;

// The hostnames must be consistent with EasyList format.
// These special RegExp characters will be escaped below: [.?+@]
// This EasyList wildcard will be transformed to an efficient RegExp: *
// 
// EasyList format references:
// https://adblockplus.org/filters
// https://adblockplus.org/filter-cheatsheet

// Create object hashes or compile efficient NFA's from all filters
// Various alternate filtering and regex approaches were timed using node and at jsperf.com

// Too many rules (>~ 10k) bog down the browser; make reasonable exclusions here:

// EasyList rules:
// https://adblockplus.org/filters
// https://adblockplus.org/filter-cheatsheet
// https://opnsrce.github.io/javascript-performance-tip-precompile-your-regular-expressions
// https://adblockplus.org/blog/investigating-filter-matching-algorithms
// 
// Strategies to convert EasyList rules to Javascript tests:
// 
// In general:
// 1. Preference for performance over 1:1 EasyList functionality
// 2. Limit number of rules to ~O(10k) to avoid computational burden on mobile devices
// 3. Exact matches: use Object hashing (very fast); use efficient NFA RegExp's for all else
// 4. Divide and conquer specific cases to avoid large RegExp's
// 5. Based on testing code performance on an iPhone: mobile Safari, Chrome with System Activity Monitor.app
// 6. Backstop these proxy.pac rules with Privoxy rules and a browser plugin
// 
// scheme://host/path?query ; FindProxyForURL(url, host) has full url and host strings
// 
// EasyList rules:
// 
// || domain anchor
// 
// ||host is exact e.g. ||a.b^ ? then hasOwnProperty(hash,host)
// ||host is wildcard e.g. ||a.* ? then RegExp.test(host)
// 
// ||host/path is exact e.g. ||a.b/c? ? then hasOwnProperty(hash,url_path_noquery) [strip ?'s]
// ||host/path is wildcard e.g. ||a.*/c? ? then RegExp.test(url_path_noquery) [strip ?'s]
// 
// ||host/path?query is exact e.g. ||a.b/c?d= ? assume none [handle small number within RegExp's]
// ||host/path?query is wildcard e.g. ||a.*/c?d= ? then RegExp.test(url)
// 
// url parts e.g. a.b^c&d|
// 
// All cases RegExp.test(url)
// Except: |http://a.b. Treat these as domain anchors after stripping the scheme
// 
// regex e.g. /r/
// 
// All cases RegExp.test(url)
// 
// @@ exceptions
// 
// Flag as "good" versus "bad" default
// 
// Variable name conventions (example that defines the rule):
// 
// bad_da_host_exact == bad domain anchor with host/path type, exact matching with Object hash
// bad_da_host_regex == bad domain anchor with host/path type, RegExp matching
// 
// 0 rules:
var good_da_host_JSON = {  };
var good_da_host_exact_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_da_host_RegExp = /^$/;
var good_da_host_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 0 rules:
var good_da_hostpath_JSON = {  };
var good_da_hostpath_exact_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_da_hostpath_RegExp = /^$/;
var good_da_hostpath_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_da_RegExp = /^$/;
var good_da_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 0 rules:
var good_da_host_exceptions_JSON = {  };
var good_da_host_exceptions_exact_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 0 rules:
var bad_da_host_JSON = {  };
var bad_da_host_exact_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var bad_da_host_RegExp = /^$/;
var bad_da_host_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// 0 rules:
var bad_da_hostpath_JSON = {  };
var bad_da_hostpath_exact_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var bad_da_hostpath_RegExp = /^$/;
var bad_da_hostpath_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 183 rules as an efficient NFA RegExp:
var bad_da_RegExp = /^(?:[\w-]+\.)*?(?:erotikdeal\.com\/\?ref=|madmimi\.com\/view\?id=|ebayrtm\.com\/rtm\?RtmCmd&a=img&|aliexpress\.com\/\?af=|yahoo\.com\/sig=|my\-dirty\-hobby\.com\/\?sub=|p\.po\.st\/p\?t=view&|vidds\.net\/\?s=promo|plista\.com\/async\/min\/video,outstream\/|bufferapp\.com\/wf\/open\?upn=|6waves\.com\/edm\.php\?uid=|overstock\.com\/dlp\?cci=|serving\-sys\.com\/Serving\?cn=display&|grammarly\.com\/embedded\?aff=|sugarops\.com\/w\?action=impression|streamtheworld\.com\/ondemand\/ars\?type=preroll|nativly\.com\/tds\/widget\?wid=|stargames\.com\/bridge\.asp\?idr=|theselfdefenseco\.com\/\?affid=|linkbucks\.com\/clean\.aspx\?task=record|api\-read\.facebook\.com\/restserver\.php\?api_key=|babylon\.com\/welcome\/index\.html\?affID=|download\-provider\.org\/\?aff\.id=|k7\-labelgroup\.com\/g\.html\?uid=|manhunt\.net\/\?dm=|juno\.com\/start\/javascript\.do\?message=|camcity\.com\/rtr\.php\?aid=|sweeva\.com\/widget\.php\?w=|heroku\.com\/\?callback=getip|freelotto\.com\/offer\.asp\?offer=|oddschecker\.com\/clickout\.htm\?type=takeover\-|fancybar\.net\/ac\/fancybar\.js\?zoneid|edomz\.com\/re\.php\?mid=|fulltiltpoker\.com\/\?key=|cursecdn\.com\/shared\-assets\/current\/anchor\.js\?id=|intagme\.com\/in\/\?u=|plista\.com\/jsmodule\/flash$|seatplans\.com\/widget$|augine\.com\/widget$|tube911\.com\/scj\/cgi\/out\.php\?scheme_id=|netreviews\.eu\/index\.php\?action=act_access&|777livecams\.com\/\?id=|ipornia\.com\/scj\/cgi\/out\.php\?scheme_id=|qualtrics\.com\/WRSiteInterceptEngine\/\?Q_Impress=|myfreecams\.com\/\?co_id=|bluehost\.com\/web\-hosting\/domaincheckapi\/\?affiliate=|urmediazone\.com\/play\?ref=|xrounds\.com\/\?lmid=|vkpass\.com\/goo\.php\?link=|vpnfortorrents\.org\/\?id=|irs01\.|exposedwebcams\.com\/\?token=|24option\.com\/\?oftc=|redlightcenter\.com\/\?trq=|affiliates2\.|s5labs\.io\/common\/i\?impressionId|hyperlinksecure\.com\/back\?token=|6angebot\.ch\/\?ref=|pinkvisualgames\.com\/\?revid=|sponsorselect\.com\/Common\/LandingPage\.aspx\?eu=|moonb\.ch\/\?ref=|sweed\.to\/\?pid=|videobox\.com\/\?tid=|exmo\.me\/\?ref=|doubleclick\.net\/imp;|xvideoslive\.com\/\?AFNO|graph\.facebook\.com\/fql\?q=SELECT|fleshlight\.com\/\?link=|movies\.askjolene\.com\/c64\?clickid=|elb\.amazonaws\.com\/\?page=|google\.com\/_\/\+1\/|affiliate\.|affiliates\.|promo\.|adv\.|piwik\.|banner\.|ads\.|banners\.|ririrrjdjjdej48484hdhdhdm|secureprovide1\.com\/(?=([\s\S]*?=tracking))\1|tinypic\.com\/api\.php\?(?=([\s\S]*?&action=track))\2|videosz\.com[^\w.%-](?=([\s\S]*?&tracker_id=))\3|bet365\.com[^\w.%-](?=([\s\S]*?affiliate=))\4|iyfsearch\.com[^\w.%-](?=([\s\S]*?&pid=))\5|casino\-x\.com[^\w.%-](?=([\s\S]*?\?partner=))\6|hulu\.com\/(?=([\s\S]*?&beaconevent))\7|flirt4free\.com[^\w.%-](?=([\s\S]*?&utm_campaign))\8|facebook\.com\/connect\/connect\.php\?(?=([\s\S]*?width))\9(?=([\s\S]*?&height))\10|waybig\.com\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\?pas=))\11|vkpass\.com\/(?=([\s\S]*?\.php\?))\12(?=([\s\S]*?=))\13|pornme\.com[^\w.%-](?=([\s\S]*?\.php\?ref=))\14|yimg\.com[^\w.%-](?=([\s\S]*?\/l\?ig=))\15|amazon\.com\/gp\/(?=([\s\S]*?&linkCode))\16|widgets\.itunes\.apple\.com[^\w.%-](?=([\s\S]*?&affiliate_id=))\17|chaturbate\.com\/(?=([\s\S]*?\/\?join_overlay=))\18|gallery\.deskbabes\.com[^\w.%-](?=([\s\S]*?\.php\?dir=))\19(?=([\s\S]*?&ids=))\20|media\.campartner\.com[^\w.%-](?=([\s\S]*?\?cp=))\21|huluim\.com\/(?=([\s\S]*?&beaconevent))\22|generic4all\.com[^\w.%-](?=([\s\S]*?\.dhtml\?refid=))\23|pornhub\.com[^\w.%-](?=([\s\S]*?&utm_campaign=))\24(?=([\s\S]*?\-pop$))\25|stargames\.com\/web\/(?=([\s\S]*?&cid=))\26(?=([\s\S]*?&pid=))\27|sexier\.com[^\w.%-](?=([\s\S]*?_popunder&))\28|trove\.com[^\w.%-](?=([\s\S]*?&uid=))\29|clickbank\.net\/(?=([\s\S]*?offer_id=))\30|msm\.mysavings\.com[^\w.%-](?=([\s\S]*?\.asp\?afid=))\31|online\.mydirtyhobby\.com[^\w.%-](?=([\s\S]*?\?naff=))\32|hop\.clickbank\.net\/(?=([\s\S]*?&transaction_id=))\33(?=([\s\S]*?&offer_id=))\34|amarotic\.com[^\w.%-](?=([\s\S]*?\?wmid=))\35(?=([\s\S]*?&kamid=))\36(?=([\s\S]*?&wsid=))\37|deb\.gs[^\w.%-](?=([\s\S]*?\?ref=))\38|stake7\.com[^\w.%-](?=([\s\S]*?\?a_aid=))\39|filmon\.com[^\w.%-](?=([\s\S]*?&adn=))\40|socialreader\.com[^\w.%-](?=([\s\S]*?\?event=email_open[^\w.%-]))\41|yellowpages\.com[^\w.%-](?=([\s\S]*?\.gif\?tid))\42|amazon\.(?=([\s\S]*?\/batch\/))\43(?=([\s\S]*?uedata=))\44|freean\.us[^\w.%-](?=([\s\S]*?\?ref=))\45|elvenar\.com[^\w.%-](?=([\s\S]*?\?ref=))\46|roblox\.com\/(?=([\s\S]*?&rbx_))\47|mmo4rpg\.com[^\w.%-](?=([\s\S]*?\.gif$))\48|r\.ypcdn\.com[^\w.%-](?=([\s\S]*?\/rtd\?ptid))\49|myspace\.com\/play\/myspace\/(?=([\s\S]*?&locationId))\50|cpm\.amateurcommunity\.(?=([\s\S]*?\?cp=))\51|torrentz\.eu\/search(?=([\s\S]*?=))\52|visit\-x\.net\/cams\/(?=([\s\S]*?\.html\?))\53(?=([\s\S]*?&s=))\54(?=([\s\S]*?&ws=))\55|facebook\.com\/restserver\.php\?(?=([\s\S]*?\.getStats&))\56|pubnub\.com\/time\/(?=([\s\S]*?uuid=))\57|eafyfsuh\.net[^\w.%-](?=([\s\S]*?\/\?name=))\58|miniurls\.co[^\w.%-](?=([\s\S]*?\?ref=))\59|get\.(?=([\s\S]*?\.website\/static\/get\-js\?stid=))\60|epornerlive\.com\/index\.php\?(?=([\s\S]*?=punder))\61|freehostedscripts\.net[^\w.%-](?=([\s\S]*?\.php\?site=))\62(?=([\s\S]*?&s=))\63(?=([\s\S]*?&h=))\64|apis\.google\.com\/_\/scs\/apps\-static\/(?=([\s\S]*?=page,plusone\/))\65|speedtestbeta\.com\/(?=([\s\S]*?\.gif\?cb))\66|seeme\.com[^\w.%-](?=([\s\S]*?\?aid=))\67(?=([\s\S]*?&art=))\68|ebayobjects\.com\/(?=([\s\S]*?;dc_pixel_url=))\69|maxedtube\.com\/video_play\?(?=([\s\S]*?&utm_campaign=))\70|amazon\.com\/\?_encoding(?=([\s\S]*?&linkcode))\71|fantasti\.cc[^\w.%-](?=([\s\S]*?\?ad=))\72|downloadprovider\.me\/en\/search\/(?=([\s\S]*?\?aff\.id=))\73(?=([\s\S]*?&iframe=))\74|civiccomputing\.com[^\w.%-](?=([\s\S]*?=cookie))\75|media\.campartner\.com\/index\.php\?cpID=(?=([\s\S]*?&cpMID=))\76|red\-tube\.com[^\w.%-](?=([\s\S]*?\.php\?wmid=))\77(?=([\s\S]*?&kamid=))\78(?=([\s\S]*?&wsid=))\79|facebook\.com\/(?=([\s\S]*?\/plugins\/send_to_messenger\.php\?app_id=))\80|plarium\.com\/play\/(?=([\s\S]*?adCampaign=))\81|trialpay\.com[^\w.%-](?=([\s\S]*?&dw\-ptid=))\82|branch\.io[^\w.%-](?=([\s\S]*?_fingerprint_id=))\83|visiblemeasures\.com\/swf\/(?=([\s\S]*?\/vmcdmplugin\.swf\?key))\84(?=([\s\S]*?pixel))\85|reviversoft\.com[^\w.%-](?=([\s\S]*?&utm_source=))\86|7host\.ru\/tr\/(?=([\s\S]*?\?r=))\87|rover\.ebay\.com[^\w.%-](?=([\s\S]*?&adtype=))\88|amarotic\.com[^\w.%-](?=([\s\S]*?\?wmid=))\89|assoc\-amazon\.(?=([\s\S]*?[^\w.%-]e\/ir\?t=))\90|google\.(?=([\s\S]*?\/url\?sa=T&source=web&cd=))\91|sextoysgfs\.com[^\w.%-](?=([\s\S]*?\?fel=))\92|postselfies\.com[^\w.%-](?=([\s\S]*?\?nats=))\93|jangomail\.com[^\w.%-](?=([\s\S]*?\?UID))\94|redplum\.com[^\w.%-](?=([\s\S]*?&pixid=))\95|stacksocial\.com[^\w.%-](?=([\s\S]*?\?aid=))\96|zazzle\.com[^\w.%-](?=([\s\S]*?\?rf))\97|tipico\.com[^\w.%-](?=([\s\S]*?\?affiliateid=))\98|porngames\.adult[^\w.%-](?=([\s\S]*?=))\99|tuberl\.com[^\w.%-](?=([\s\S]*?=))\100|cyberprotection\.pro[^\w.%-](?=([\s\S]*?\?aff))\101|lovepoker\.de[^\w.%-](?=([\s\S]*?\/\?pid=))\102|doubleclick\.net\/pfadx\/(?=([\s\S]*?adcat=))\103|exashare\.com[^\w.%-](?=([\s\S]*?&h=))\104|fuckshow\.org[^\w.%-](?=([\s\S]*?&adr=))\105|generic4all\.com[^\w.%-](?=([\s\S]*?\?refid=))\106|fuckhub\.net[^\w.%-](?=([\s\S]*?\?pid=))\107|fleshlight\-international\.eu[^\w.%-](?=([\s\S]*?\?link=))\108|tipico\.(?=([\s\S]*?\?affiliateId=))\109|dateoffer\.net\/\?s=(?=([\s\S]*?&subid=))\110|casino\-x\.com[^\w.%-](?=([\s\S]*?&promo))\111|ifly\.com\/trip\-plan\/ifly\-trip\?(?=([\s\S]*?&ad=))\112|ipornia\.com\/(?=([\s\S]*?=))\113(?=([\s\S]*?&))\114|doubleclick\.net\/adj\/(?=([\s\S]*?\.collegehumor\/sec=videos_originalcontent;))\115|linkbucks\.com[^\w.%-](?=([\s\S]*?\/\?))\116(?=([\s\S]*?=))\117|allmyvideos\.net\/(?=([\s\S]*?=))\118|cts\.tradepub\.com\/cts4\/\?ptnr=(?=([\s\S]*?&tm=))\119|mjtlive\.com\/exports\/golive\/\?lp=(?=([\s\S]*?&afno=))\120|doubleclick\.net[^\w.%-](?=([\s\S]*?;afv_flvurl=http\:\/\/cdn\.c\.ooyala\.com\/))\121|quantserve\.com[^\w.%-](?=([\s\S]*?[^\w.%-]a=))\122|theseforums\.com[^\w.%-](?=([\s\S]*?\/\?ref=))\123)/i;
var bad_da_regex_flag = 183 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_url_parts_RegExp = /^$/;
var good_url_parts_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var bad_url_parts_RegExp = /^$/;
var bad_url_parts_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_url_RegExp = /^$/;
var good_url_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var bad_url_RegExp = /^$/;
var bad_url_regex_flag = 0 > 0 ? true : false;  // test for non-zero number of rules

// Add any good networks here. Format is network folowed by a comma and
// optional white space, and then the netmask.
// LAN, loopback, Apple (direct and Akamai e.g. e4805.a.akamaiedge.net), Microsoft (updates and services)
var GoodNetworks_Array = [];

// Apple iAd, Microsoft telemetry
var GoodNetworks_Exceptions_Array = [];

// Akamai: 23.64.0.0/14, 23.0.0.0/12, 23.32.0.0/11, 104.64.0.0/10

// Add any bad networks here. Format is network folowed by a comma and
// optional white space, and then the netmask.
// From securemecca.com: Adobe marketing cloud, 2o7, omtrdc, Sedo domain parking, flyingcroc, accretive
var BadNetworks_Array = [];

// block these schemes; use the command line for ftp, rsync, etc. instead
var bad_schemes_RegExp = RegExp("^(?:ftp|sftp|tftp|ftp-data|rsync|finger|gopher)", "i")

// RegExp for schemes; lengths from
// perl -lane 'BEGIN{$l=0;} {!/^#/ && do{$ll=length($F[0]); if($ll>$l){$l=$ll;}};} END{print $l;}' /etc/services
var schemepart_RegExp = RegExp("^([\\w*+-]{2,15}):\\/{0,2}","i");
var hostpart_RegExp = RegExp("^((?:[\\w-]+\\.)+[a-zA-Z0-9-]{2,24}\\.?)", "i");
var querypart_RegExp = RegExp("^((?:[\\w-]+\\.)+[a-zA-Z0-9-]{2,24}\\.?[\\w~%.\\/^*-]*)(\\??\\S*?)$", "i");
var domainpart_RegExp = RegExp("^(?:[\\w-]+\\.)*((?:[\\w-]+\\.)[a-zA-Z0-9-]{2,24})\\.?", "i");

//////////////////////////////////////////////////
// Define the is_ipv4_address function and vars //
//////////////////////////////////////////////////

var ipv4_RegExp = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function is_ipv4_address(host)
{
    var ipv4_pentary = host.match(ipv4_RegExp);
    var is_valid_ipv4 = false;

    if (ipv4_pentary) {
        is_valid_ipv4 = true;
        for( i = 1; i <= 4; i++) {
            if (ipv4_pentary[i] >= 256) {
                is_valid_ipv4 = false;
            }
        }
    }
    return is_valid_ipv4;
}

// object hashes
// Note: original stackoverflow-based hasOwnProperty does not woth within iOS kernel 
var hasOwnProperty = function(obj, prop) {
    return obj.hasOwnProperty(prop);
}

/////////////////////
// Done Setting Up //
/////////////////////

// debug with Chrome at chrome://net-export
// alert("Debugging message.")

//////////////////////////////////
// Define the FindProxyFunction //
//////////////////////////////////

var use_pass_rules_parts_flag = true;  // use the pass rules for url parts, then apply the block rules
var alert_flag = false;                // use for short-circuit '&&' to print debugging statements
var debug_flag = false;               // use for short-circuit '&&' to print debugging statements

// EasyList filtering for FindProxyForURL(url, host)
function EasyListFindProxyForURL(url, host)
{
    var host_is_ipv4 = is_ipv4_address(host);
    var host_ipv4_address;

    alert_flag && alert("url is: " + url);
    alert_flag && alert("host is: " + host);

    // Extract scheme and url without scheme
    var scheme = url.match(schemepart_RegExp)
    scheme = scheme.length > 0? scheme[1] : "";

    // Remove the scheme and extract the path for regex efficiency
    var url_noscheme = url.replace(schemepart_RegExp,"");
    var url_pathonly = url_noscheme.replace(hostpart_RegExp,"");
    var url_noquery = url_noscheme.replace(querypart_RegExp,"$1");
    // Remove the server name from the url and host if host is not an IPv4 address
    var url_noserver = !host_is_ipv4 ? url_noscheme.replace(domainpart_RegExp,"$1") : url_noscheme;
    var url_noservernoquery = !host_is_ipv4 ? url_noquery.replace(domainpart_RegExp,"$1") : url_noscheme;
    var host_noserver =  !host_is_ipv4 ? host.replace(domainpart_RegExp,"$1") : host;

    // Debugging results
    if (debug_flag && alert_flag) {
        alert("url_noscheme is: " + url_noscheme);
        alert("url_pathonly is: " + url_pathonly);
        alert("url_noquery is: " + url_noquery);
        alert("url_noserver is: " + url_noserver);
        alert("url_noservernoquery is: " + url_noservernoquery);
        alert("host_noserver is: " + host_noserver);
    }

    // Short circuit to blackhole for good_da_host_exceptions
    if ( hasOwnProperty(good_da_host_exceptions_JSON,host) ) {
        alert_flag && alert("good_da_host_exceptions_JSON blackhole!");
        return blackhole;
    }

    ///////////////////////////////////////////////////////////////////////
    // Check to make sure we can get an IPv4 address from the given host //
    // name.  If we cannot do that then skip the Networks tests.         //
    ///////////////////////////////////////////////////////////////////////

    host_ipv4_address = host_is_ipv4 ? host : (isResolvable(host) ? dnsResolve(host) : false);

    if (host_ipv4_address) {
        alert_flag && alert("host ipv4 address is: " + host_ipv4_address);
        /////////////////////////////////////////////////////////////////////////////
        // If the IP translates to one of the GoodNetworks_Array (with exceptions) //
        // we pass it because it is considered safe.                               //
        /////////////////////////////////////////////////////////////////////////////

        for (i in GoodNetworks_Exceptions_Array) {
            tmpNet = GoodNetworks_Exceptions_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("GoodNetworks_Exceptions_Array Blackhole: " + host_ipv4_address);
                return blackhole;
            }
        }
        for (i in GoodNetworks_Array) {
            tmpNet = GoodNetworks_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("GoodNetworks_Array PASS: " + host_ipv4_address);
                return proxy;
            }
        }

        ///////////////////////////////////////////////////////////////////////
        // If the IP translates to one of the BadNetworks_Array we fail it   //
        // because it is not considered safe.                                //
        ///////////////////////////////////////////////////////////////////////

        for (i in BadNetworks_Array) {
            tmpNet = BadNetworks_Array[i].split(/,\s*/);
            if (isInNet(host_ipv4_address, tmpNet[0], tmpNet[1])) {
                alert_flag && alert("BadNetworks_Array Blackhole: " + host_ipv4_address);
                return blackhole;
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////////
    // HTTPS: https scheme can only use domain information                      //
    // unless PacHttpsUrlStrippingEnabled == false [Chrome] or                  //
    // network.proxy.autoconfig_url.include_path == true [Firefox, about:config]              //
    // E.g. on macOS:                                                           //
    // defaults write com.google.Chrome PacHttpsUrlStrippingEnabled -bool false //
    // Check setting at page chrome://policy                                    //
    //////////////////////////////////////////////////////////////////////////////

    // Assume browser has disabled path access if scheme is https and path is '/'
    if ( scheme == "https" && url_pathonly == "/" ) {

        ///////////////////////////////////////////////////////////////////////
        // PASS LIST:   domains matched here will always be allowed.         //
        ///////////////////////////////////////////////////////////////////////

        if ( (good_da_host_exact_flag && (hasOwnProperty(good_da_host_JSON,host_noserver)||hasOwnProperty(good_da_host_JSON,host)))
            && !hasOwnProperty(good_da_host_exceptions_JSON,host) ) {
                alert_flag && alert("HTTPS PASS: " + host + ", " + host_noserver);
            return proxy;
        }

        //////////////////////////////////////////////////////////
        // BLOCK LIST:	stuff matched here here will be blocked //
        //////////////////////////////////////////////////////////

        if ( (bad_da_host_exact_flag && (hasOwnProperty(bad_da_host_JSON,host_noserver)||hasOwnProperty(bad_da_host_JSON,host))) ) {
            alert_flag && alert("HTTPS blackhole: " + host + ", " + host_noserver);
            return blackhole;
        }
    }

    ////////////////////////////////////////
    // HTTPS and HTTP: full path analysis //
    ////////////////////////////////////////

    if (scheme == "https" || scheme == "http") {

        ///////////////////////////////////////////////////////////////////////
        // PASS LIST:   domains matched here will always be allowed.         //
        ///////////////////////////////////////////////////////////////////////

        if ( !hasOwnProperty(good_da_host_exceptions_JSON,host)
            && ((good_da_host_exact_flag && (hasOwnProperty(good_da_host_JSON,host_noserver)||hasOwnProperty(good_da_host_JSON,host))) ||  // fastest test first
                (use_pass_rules_parts_flag &&
                    (good_da_hostpath_exact_flag && (hasOwnProperty(good_da_hostpath_JSON,url_noservernoquery)||hasOwnProperty(good_da_hostpath_JSON,url_noquery)) ) ||
                    // test logic: only do the slower test if the host has a (non)suspect fqdn
                    (good_da_host_regex_flag && (good_da_host_RegExp.test(host_noserver)||good_da_host_RegExp.test(host))) ||
                    (good_da_hostpath_regex_flag && (good_da_hostpath_RegExp.test(url_noservernoquery)||good_da_hostpath_RegExp.test(url_noquery))) ||
                    (good_da_regex_flag && (good_da_RegExp.test(url_noserver)||good_da_RegExp.test(url_noscheme))) ||
                    (good_url_parts_flag && good_url_parts_RegExp.test(url)) ||
                    (good_url_regex_flag && good_url_regex_RegExp.test(url)))) ) {
            return proxy;
        }

        //////////////////////////////////////////////////////////
        // BLOCK LIST:	stuff matched here here will be blocked //
        //////////////////////////////////////////////////////////
        // Debugging results
        if (debug_flag && alert_flag) {
            alert("hasOwnProperty(bad_da_host_JSON," + host_noserver + "): " + (bad_da_host_exact_flag && hasOwnProperty(bad_da_host_JSON,host_noserver)));
            alert("hasOwnProperty(bad_da_host_JSON," + host + "): " + (bad_da_host_exact_flag && hasOwnProperty(bad_da_host_JSON,host)));
            alert("hasOwnProperty(bad_da_hostpath_JSON," + url_noservernoquery + "): " + (bad_da_hostpath_exact_flag && hasOwnProperty(bad_da_hostpath_JSON,url_noservernoquery)));
            alert("hasOwnProperty(bad_da_hostpath_JSON," + url_noquery + "): " + (bad_da_hostpath_exact_flag && hasOwnProperty(bad_da_hostpath_JSON,url_noquery)));
            alert("bad_da_host_RegExp.test(" + host_noserver + "): " + (bad_da_host_regex_flag && bad_da_host_RegExp.test(host_noserver)));
            alert("bad_da_host_RegExp.test(" + host + "): " + (bad_da_host_regex_flag && bad_da_host_RegExp.test(host)));
            alert("bad_da_hostpath_RegExp.test(" + url_noservernoquery + "): " + (bad_da_hostpath_regex_flag && bad_da_hostpath_RegExp.test(url_noservernoquery)));
            alert("bad_da_hostpath_RegExp.test(" + url_noquery + "): " + (bad_da_hostpath_regex_flag && bad_da_hostpath_RegExp.test(url_noquery)));
            alert("bad_da_RegExp.test(" + url_noserver + "): " + (bad_da_regex_flag && bad_da_RegExp.test(url_noserver)));
            alert("bad_da_RegExp.test(" + url_noscheme + "): " + (bad_da_regex_flag && bad_da_RegExp.test(url_noscheme)));
            alert("bad_url_parts_RegExp.test(" + url + "): " + (bad_url_parts_flag && bad_url_parts_RegExp.test(url)));
            alert("bad_url_regex_RegExp.test(" + url + "): " + (bad_url_regex_flag && bad_url_regex_RegExp.test(url)));
        }

        if ( (bad_da_host_exact_flag && (hasOwnProperty(bad_da_host_JSON,host_noserver)||hasOwnProperty(bad_da_host_JSON,host))) ||  // fastest test first
            (bad_da_hostpath_exact_flag && (hasOwnProperty(bad_da_hostpath_JSON,url_noservernoquery)||hasOwnProperty(bad_da_hostpath_JSON,url_noquery)) ) ||
            // test logic: only do the slower test if the host has a (non)suspect fqdn
            (bad_da_host_regex_flag && (bad_da_host_RegExp.test(host_noserver)||bad_da_host_RegExp.test(host))) ||
            (bad_da_hostpath_regex_flag && (bad_da_hostpath_RegExp.test(url_noservernoquery)||bad_da_hostpath_RegExp.test(url_noquery))) ||
            (bad_da_regex_flag && (bad_da_RegExp.test(url_noserver)||bad_da_RegExp.test(url_noscheme))) ||
            (bad_url_parts_flag && bad_url_parts_RegExp.test(url)) ||
            (bad_url_regex_flag && bad_url_regex_RegExp.test(url)) ) {
            alert_flag && alert("Blackhole: " + url + ", " + host);
            return blackhole;
        }
    }

    // default pass
    alert_flag && alert("Default PASS: " + url + ", " + host);
    return proxy;
}

// User-supplied FindProxyForURL()
function FindProxyForURL(url, host)
{
if (
   isPlainHostName(host) ||
   shExpMatch(host, "10.*") ||
   shExpMatch(host, "172.16.*") ||
   shExpMatch(host, "192.168.*") ||
   shExpMatch(host, "127.*") ||
   dnsDomainIs(host, ".LOCAL") ||
   dnsDomainIs(host, ".local") ||
   (url.substring(0,4) == "ftp:")
)
        return "DIRECT";
else
        return EasyListFindProxyForURL(url, host);
}   
