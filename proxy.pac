//Wed, 22 May 2019 23:29:17 GMT
//elph -d /scripts/github/proxy/ -b 1.1.1.1:53
var normal = "DIRECT";
var proxy = "DIRECT";                  // e.g. 127.0.0.1:3128
var blackhole_ip_port = "1.1.1.1:53";    // on iOS a working blackhole requires return code 200;
var blackhole = "PROXY " + blackhole_ip_port;

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
    
// 136 rules as an efficient NFA RegExp:
var bad_da_RegExp = /^(?:[\w-]+\.)*?(?:erotikdeal\.com\/\?ref=|aliexpress\.com\/\?af=|ebayrtm\.com\/rtm\?RtmCmd&a=img&|p\.po\.st\/p\?t=view&|vidds\.net\/\?s=promo|yahoo\.com\/sig=|my\-dirty\-hobby\.com\/\?sub=|plista\.com\/async\/min\/video,outstream\/|6waves\.com\/edm\.php\?uid=|grammarly\.com\/embedded\?aff=|nativly\.com\/tds\/widget\?wid=|sugarops\.com\/w\?action=impression|overstock\.com\/dlp\?cci=|stargames\.com\/bridge\.asp\?idr=|sweeva\.com\/widget\.php\?w=|serving\-sys\.com\/Serving\?cn=display&|madmimi\.com\/view\?id=|k7\-labelgroup\.com\/g\.html\?uid=|streamtheworld\.com\/ondemand\/ars\?type=preroll|linkbucks\.com\/clean\.aspx\?task=record|manhunt\.net\/\?dm=|theselfdefenseco\.com\/\?affid=|babylon\.com\/welcome\/index\.html\?affID=|seatplans\.com\/widget$|augine\.com\/widget$|download\-provider\.org\/\?aff\.id=|heroku\.com\/\?callback=getip|camcity\.com\/rtr\.php\?aid=|juno\.com\/start\/javascript\.do\?message=|oddschecker\.com\/clickout\.htm\?type=takeover\-|edomz\.com\/re\.php\?mid=|freelotto\.com\/offer\.asp\?offer=|plista\.com\/jsmodule\/flash$|fulltiltpoker\.com\/\?key=|fancybar\.net\/ac\/fancybar\.js\?zoneid|netreviews\.eu\/index\.php\?action=act_access&|qualtrics\.com\/WRSiteInterceptEngine\/\?Q_Impress=|myfreecams\.com\/\?co_id=|urmediazone\.com\/play\?ref=|bluehost\.com\/web\-hosting\/domaincheckapi\/\?affiliate=|redlightcenter\.com\/\?trq=|xrounds\.com\/\?lmid=|irs01\.|exposedwebcams\.com\/\?token=|bufferapp\.com\/wf\/open\?upn=|affiliates2\.|6angebot\.ch\/\?ref=|vpnfortorrents\.org\/\?id=|777livecams\.com\/\?id=|24option\.com\/\?oftc=|vkpass\.com\/goo\.php\?link=|pinkvisualgames\.com\/\?revid=|s5labs\.io\/common\/i\?impressionId|sponsorselect\.com\/Common\/LandingPage\.aspx\?eu=|cursecdn\.com\/shared\-assets\/current\/anchor\.js\?id=|moonb\.ch\/\?ref=|hyperlinksecure\.com\/back\?token=|videosz\.com[^\w.%-](?=([\s\S]*?&tracker_id=))\1|secureprovide1\.com\/(?=([\s\S]*?=tracking))\2|tinypic\.com\/api\.php\?(?=([\s\S]*?&action=track))\3|iyfsearch\.com[^\w.%-](?=([\s\S]*?&pid=))\4|casino\-x\.com[^\w.%-](?=([\s\S]*?\?partner=))\5|flirt4free\.com[^\w.%-](?=([\s\S]*?&utm_campaign))\6|hulu\.com\/(?=([\s\S]*?&beaconevent))\7|waybig\.com\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\?pas=))\8|pornme\.com[^\w.%-](?=([\s\S]*?\.php\?ref=))\9|vkpass\.com\/(?=([\s\S]*?\.php\?))\10(?=([\s\S]*?=))\11|amazon\.com\/gp\/(?=([\s\S]*?&linkCode))\12|widgets\.itunes\.apple\.com[^\w.%-](?=([\s\S]*?&affiliate_id=))\13|yimg\.com[^\w.%-](?=([\s\S]*?\/l\?ig=))\14|gallery\.deskbabes\.com[^\w.%-](?=([\s\S]*?\.php\?dir=))\15(?=([\s\S]*?&ids=))\16|chaturbate\.com\/(?=([\s\S]*?\/\?join_overlay=))\17|huluim\.com\/(?=([\s\S]*?&beaconevent))\18|generic4all\.com[^\w.%-](?=([\s\S]*?\.dhtml\?refid=))\19|sexier\.com[^\w.%-](?=([\s\S]*?_popunder&))\20|pornhub\.com[^\w.%-](?=([\s\S]*?&utm_campaign=))\21(?=([\s\S]*?\-pop$))\22|media\.campartner\.com[^\w.%-](?=([\s\S]*?\?cp=))\23|stargames\.com\/web\/(?=([\s\S]*?&cid=))\24(?=([\s\S]*?&pid=))\25|stake7\.com[^\w.%-](?=([\s\S]*?\?a_aid=))\26|filmon\.com[^\w.%-](?=([\s\S]*?&adn=))\27|trove\.com[^\w.%-](?=([\s\S]*?&uid=))\28|roblox\.com\/(?=([\s\S]*?&rbx_))\29|online\.mydirtyhobby\.com[^\w.%-](?=([\s\S]*?\?naff=))\30|bet365\.com[^\w.%-](?=([\s\S]*?affiliate=))\31|deb\.gs[^\w.%-](?=([\s\S]*?\?ref=))\32|clickbank\.net\/(?=([\s\S]*?offer_id=))\33|hop\.clickbank\.net\/(?=([\s\S]*?&transaction_id=))\34(?=([\s\S]*?&offer_id=))\35|amarotic\.com[^\w.%-](?=([\s\S]*?\?wmid=))\36(?=([\s\S]*?&kamid=))\37(?=([\s\S]*?&wsid=))\38|socialreader\.com[^\w.%-](?=([\s\S]*?\?event=email_open[^\w.%-]))\39|elvenar\.com[^\w.%-](?=([\s\S]*?\?ref=))\40|msm\.mysavings\.com[^\w.%-](?=([\s\S]*?\.asp\?afid=))\41|amazon\.(?=([\s\S]*?\/batch\/))\42(?=([\s\S]*?uedata=))\43|mmo4rpg\.com[^\w.%-](?=([\s\S]*?\.gif$))\44|freean\.us[^\w.%-](?=([\s\S]*?\?ref=))\45|eafyfsuh\.net[^\w.%-](?=([\s\S]*?\/\?name=))\46|r\.ypcdn\.com[^\w.%-](?=([\s\S]*?\/rtd\?ptid))\47|yellowpages\.com[^\w.%-](?=([\s\S]*?\.gif\?tid))\48|miniurls\.co[^\w.%-](?=([\s\S]*?\?ref=))\49|speedtestbeta\.com\/(?=([\s\S]*?\.gif\?cb))\50|torrentz\.eu\/search(?=([\s\S]*?=))\51|cpm\.amateurcommunity\.(?=([\s\S]*?\?cp=))\52|get\.(?=([\s\S]*?\.website\/static\/get\-js\?stid=))\53|visit\-x\.net\/cams\/(?=([\s\S]*?\.html\?))\54(?=([\s\S]*?&s=))\55(?=([\s\S]*?&ws=))\56|myspace\.com\/play\/myspace\/(?=([\s\S]*?&locationId))\57|media\.campartner\.com\/index\.php\?cpID=(?=([\s\S]*?&cpMID=))\58|branch\.io[^\w.%-](?=([\s\S]*?_fingerprint_id=))\59|maxedtube\.com\/video_play\?(?=([\s\S]*?&utm_campaign=))\60|seeme\.com[^\w.%-](?=([\s\S]*?\?aid=))\61(?=([\s\S]*?&art=))\62|epornerlive\.com\/index\.php\?(?=([\s\S]*?=punder))\63|amazon\.com\/\?_encoding(?=([\s\S]*?&linkcode))\64|trialpay\.com[^\w.%-](?=([\s\S]*?&dw\-ptid=))\65|freehostedscripts\.net[^\w.%-](?=([\s\S]*?\.php\?site=))\66(?=([\s\S]*?&s=))\67(?=([\s\S]*?&h=))\68|exashare\.com[^\w.%-](?=([\s\S]*?&h=))\69|plarium\.com\/play\/(?=([\s\S]*?adCampaign=))\70|amarotic\.com[^\w.%-](?=([\s\S]*?\?wmid=))\71|red\-tube\.com[^\w.%-](?=([\s\S]*?\.php\?wmid=))\72(?=([\s\S]*?&kamid=))\73(?=([\s\S]*?&wsid=))\74|reviversoft\.com[^\w.%-](?=([\s\S]*?&utm_source=))\75|fantasti\.cc[^\w.%-](?=([\s\S]*?\?ad=))\76|rover\.ebay\.com[^\w.%-](?=([\s\S]*?&adtype=))\77|visiblemeasures\.com\/swf\/(?=([\s\S]*?\/vmcdmplugin\.swf\?key))\78(?=([\s\S]*?pixel))\79|downloadprovider\.me\/en\/search\/(?=([\s\S]*?\?aff\.id=))\80(?=([\s\S]*?&iframe=))\81|sextoysgfs\.com[^\w.%-](?=([\s\S]*?\?fel=))\82|7host\.ru\/tr\/(?=([\s\S]*?\?r=))\83|ebayobjects\.com\/(?=([\s\S]*?;dc_pixel_url=))\84|postselfies\.com[^\w.%-](?=([\s\S]*?\?nats=))\85|assoc\-amazon\.(?=([\s\S]*?[^\w.%-]e\/ir\?t=))\86|tipico\.com[^\w.%-](?=([\s\S]*?\?affiliateid=))\87|stacksocial\.com[^\w.%-](?=([\s\S]*?\?aid=))\88|lovepoker\.de[^\w.%-](?=([\s\S]*?\/\?pid=))\89|jangomail\.com[^\w.%-](?=([\s\S]*?\?UID))\90|redplum\.com[^\w.%-](?=([\s\S]*?&pixid=))\91|zazzle\.com[^\w.%-](?=([\s\S]*?\?rf))\92|cyberprotection\.pro[^\w.%-](?=([\s\S]*?\?aff))\93|porngames\.adult[^\w.%-](?=([\s\S]*?=))\94|casino\-x\.com[^\w.%-](?=([\s\S]*?&promo))\95|tuberl\.com[^\w.%-](?=([\s\S]*?=))\96)/i;
var bad_da_regex_flag = 136 > 0 ? true : false;  // test for non-zero number of rules
    
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

var GoodNetworks_Array = [ "10.0.0.0,     255.0.0.0",
"192.168.0.0,       255.255.0.0",
"127.0.0.0,         255.0.0.0"];

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
