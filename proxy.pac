// PAC file created on Thu, 13 Jun 2019 16:19:52 GMT
// Created with command: good-easylist_pac -d /scripts/github/proxy/
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
var blackhole_ip_port = "127.0.0.1:8119";    // on iOS a working blackhole requires return code 200;
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

// 200 rules:
var bad_da_host_JSON = { "content.ad": null,
"exoclick.com": null,
"nastydollars.com": null,
"webvisor.ru": null,
"adziff.com": null,
"sharethrough.com": null,
"tsyndicate.com": null,
"dianomi.com": null,
"amazon-adsystem.com": null,
"moatads.com": null,
"adsafeprotected.com": null,
"ad.doubleclick.net": null,
"2mdn.net": null,
"go.megabanners.cf": null,
"pagead2.googlesyndication.com": null,
"doubleclick.net": null,
"adchemy-content.com": null,
"admitad.com": null,
"ltassrv.com.s3.amazonaws.com": null,
"serving-sys.com": null,
"adap.tv": null,
"ip-adress.com": null,
"g00.msn.com": null,
"optimizely.com": null,
"contentspread.net": null,
"advertising.com": null,
"chartbeat.com": null,
"click.aliexpress.com": null,
"scorecardresearch.com": null,
"media.net": null,
"quantserve.com": null,
"static.parsely.com": null,
"coinad.com": null,
"nuggad.net": null,
"teads.tv": null,
"stroeerdigitalmedia.de": null,
"webtrekk.net": null,
"imasdk.googleapis.com": null,
"rlcdn.com": null,
"mxcdn.net": null,
"smartadserver.com": null,
"clicktale.net": null,
"flashtalking.com": null,
"movad.net": null,
"adnxs.com": null,
"krxd.net": null,
"visualwebsiteoptimizer.com": null,
"adverserve.net": null,
"intelliad.de": null,
"gitcdn.pw": null,
"adult.xyz": null,
"d11a2fzhgzqe7i.cloudfront.net": null,
"log.pinterest.com": null,
"crwdcntrl.net": null,
"hotjar.com": null,
"imglnkc.com": null,
"3lift.com": null,
"ace.advertising.com": null,
"revcontent.com": null,
"banners.cams.com": null,
"adition.com": null,
"mediaplex.com": null,
"cm.g.doubleclick.net": null,
"cpx.to": null,
"adform.net": null,
"eclick.baidu.com": null,
"xxlargepop.com": null,
"bluekai.com": null,
"openx.net": null,
"dashad.io": null,
"ad.proxy.sh": null,
"lw2.gamecopyworld.com": null,
"adapd.com": null,
"adfox.yandex.ru": null,
"bongacams.com": null,
"traffic.focuusing.com": null,
"firstclass-download.com": null,
"adspayformymortgage.win": null,
"trmnsite.com": null,
"ebayobjects.com.au": null,
"pdheuryopd.loan": null,
"clickopop1000.com": null,
"nkmsite.com": null,
"yinmyar.xyz": null,
"abbp1.website": null,
"videoplaza.com": null,
"uoldid.ru": null,
"money-maker-script.info": null,
"money-maker-default.info": null,
"kdmkauchahynhrs.ru": null,
"ad.rambler.ru": null,
"cashbigo.com": null,
"megabanners.cf": null,
"abbp1.science": null,
"pos.baidu.com": null,
"ads.yahoo.com": null,
"creativecdn.com": null,
"freecontent.download": null,
"smallseotools.com": null,
"ct.pinterest.com": null,
"ero-advertising.com": null,
"adup-tech.com": null,
"log.outbrain.com": null,
"getclicky.com": null,
"metrics.brightcove.com": null,
"chartaca.com.s3.amazonaws.com": null,
"dnn506yrbagrg.cloudfront.net": null,
"bzclk.baidu.com": null,
"gsp1.baidu.com": null,
"pixel.facebook.com": null,
"videoplaza.tv": null,
"popads.net": null,
"adv.drtuber.com": null,
"prpops.com": null,
"hpr.outbrain.com": null,
"hornymatches.com": null,
"juicyads.com": null,
"advertserve.com": null,
"tracking-rce.veeseo.com": null,
"3wr110.xyz": null,
"adblade.com": null,
"htmlhubing.xyz": null,
"adk2.co": null,
"xclicks.net": null,
"mobsterbird.info": null,
"explainidentifycoding.info": null,
"am10.ru": null,
"adtrace.org": null,
"utarget.ru": null,
"shareasale.com": null,
"bontent.powvideo.net": null,
"clicksor.net": null,
"popwin.net": null,
"rapidyl.net": null,
"insta-cash.net": null,
"clicksor.com": null,
"adonweb.ru": null,
"kissmetrics.com": null,
"adk2.com": null,
"hd-plugin.com": null,
"contentabc.com": null,
"admedit.net": null,
"propellerpops.com": null,
"liveadexchanger.com": null,
"ringtonematcher.com": null,
"superadexchange.com": null,
"downloadboutique.com": null,
"adjuggler.net": null,
"adexc.net": null,
"sexad.net": null,
"tagcdn.com": null,
"adcash.com": null,
"clickmngr.com": null,
"xtendmedia.com": null,
"onad.eu": null,
"clickosmedia.com": null,
"traffictraffickers.com": null,
"click.scour.com": null,
"clicktripz.com": null,
"sharecash.org": null,
"media-servers.net": null,
"888media.net": null,
"traktrafficflow.com": null,
"ad6media.fr": null,
"advmedialtd.com": null,
"adultadmedia.com": null,
"widget.yavli.com": null,
"onclickads.net": null,
"track.xtrasize.nl": null,
"brandreachsys.com": null,
"adcdnx.com": null,
"traffichaus.com": null,
"trafficshop.com": null,
"fpctraffic2.com": null,
"trafficforce.com": null,
"yieldtraffic.com": null,
"trafficholder.com": null,
"pointclicktrack.com": null,
"wigetmedia.com": null,
"waframedia5.com": null,
"mediaseeding.com": null,
"pgmediaserve.com": null,
"toroadvertisingmedia.com": null,
"livepromotools.com": null,
"youradexchange.com": null,
"adbooth.com": null,
"360adstrack.com": null,
"adscpm.net": null,
"ringtonepartner.com": null,
"bettingpartners.com": null,
"adsrv4k.com": null,
"adsurve.com": null,
"adservme.com": null,
"adsupply.com": null,
"adserverplus.com": null,
"clickfuse.com": null,
"clicksgear.com": null,
"onclickmax.com": null,
"poponclick.com": null,
"clicksvenue.com": null };
var bad_da_host_exact_flag = 200 > 0 ? true : false;  // test for non-zero number of rules
    
// 30 rules as an efficient NFA RegExp:
var bad_da_host_RegExp = /^(?:[\w-]+\.)*?(?:tracker(?=([\s\S]*?\.richcasino\.com))\1|tracking(?=([\s\S]*?\.euroads\.fi))\2|tracker(?=([\s\S]*?\.bingohall\.ag))\3|tracking\.(?=([\s\S]*?\.miui\.com))\4|analytics\-beacon\-(?=([\s\S]*?\.amazonaws\.com))\5|rcm(?=([\s\S]*?\.amazon\.))\6|stats\-(?=([\s\S]*?\.p2pnow\.ru))\7|datacollect(?=([\s\S]*?\.abtasty\.com))\8|plundermedia\.com(?=([\s\S]*?rectangle\-))\9|images\.(?=([\s\S]*?\.criteo\.net))\10|ads\-(?=([\s\S]*?\.hulu\.com))\11|metro\-trending\-(?=([\s\S]*?\.amazonaws\.com))\12|log\-(?=([\s\S]*?\.previewnetworks\.com))\13|stats2\.(?=([\s\S]*?\.fdnames\.com))\14|trk(?=([\s\S]*?\.vidible\.tv))\15|vtnlog\-(?=([\s\S]*?\.elb\.amazonaws\.com))\16|banners(?=([\s\S]*?\.spacash\.com))\17|metric(?=([\s\S]*?\.rediff\.com))\18|mobileoffers\-(?=([\s\S]*?\-download\.com))\19|sextronix\.(?=([\s\S]*?\.cdnaccess\.com))\20|adr\-(?=([\s\S]*?\.vindicosuite\.com))\21|logger\-(?=([\s\S]*?\.dailymotion\.com))\22|log(?=([\s\S]*?\.ku6\.com))\23|vix\.(?=([\s\S]*?\.criteo\.net))\24|collector\-(?=([\s\S]*?\.elb\.amazonaws\.com))\25|collector\-(?=([\s\S]*?\.tvsquared\.com))\26|anet(?=([\s\S]*?\.tradedoubler\.com))\27|minero\-proxy\-(?=([\s\S]*?\.sh))\28|imp(?=([\s\S]*?\.tradedoubler\.com))\29|(?=([\s\S]*?\.googlesyndication\.com))\30)/i;
var bad_da_host_regex_flag = 30 > 0 ? true : false;  // test for non-zero number of rules

// 200 rules:
var bad_da_hostpath_JSON = { "depositfiles.com/stats.php": null,
"google-analytics.com/analytics.js": null,
"ad.atdmt.com/i/a.js": null,
"ad.atdmt.com/i/a.html": null,
"cloudfront.net/analytics.js": null,
"googletagmanager.com/gtm.js": null,
"hulkshare.com/stats.php": null,
"baidu.com/h.js": null,
"domaintools.com/tracker.php": null,
"baidu.com/js/log.js": null,
"linkconnector.com/traffic_record.php": null,
"elb.amazonaws.com/partner.gif": null,
"imagesnake.com/includes/js/pops.js": null,
"thefile.me/apu.php": null,
"twitvid.com/api/tracking.php": null,
"wheninmanila.com/wp-content/uploads/2012/12/Marie-France-Buy-1-Take-1-Deal-Discount-WhenInManila.jpg": null,
"autoline-top.com/counter.php": null,
"cloudfront.net/log.js": null,
"pluso.ru/counter.php": null,
"viglink.com/images/pixel.gif": null,
"disqus.com/stats.html": null,
"facebook.com/common/scribe_endpoint.php": null,
"movad.de/c.ount": null,
"plista.com/iframeShowItem.php": null,
"myway.com/gca_iframe.html": null,
"cloudfront.net/scripts/js3caf.js": null,
"codecguide.com/stats.js": null,
"elb.amazonaws.com/small.gif": null,
"amazonaws.com/g.aspx": null,
"tubepornclassic.com/js/111.js": null,
"eastmoney.com/counter.js": null,
"dpstatic.com/banner.png": null,
"eageweb.com/stats.php": null,
"cgmlab.com/tools/geotarget/custombanner.js": null,
"piano-media.com/bucket/novosense.swf": null,
"cloudfront.net/js/reach.js": null,
"brightcove.com/1pix.gif": null,
"googletagservices.com/dcm/dcmads.js": null,
"ge.com/sites/all/themes/ge_2012/assets/js/bin/s_code.js": null,
"hitleap.com/assets/banner.png": null,
"analpornpix.com/agent.php": null,
"mercola.com/Assets/js/omniture/sitecatalyst/mercola_s_code.js": null,
"snazzyspace.com/generators/viewer-counter/counter.php": null,
"s-msn.com/s/js/loader/activity/trackloader.min.js": null,
"baymirror.com/static/img/bar.gif": null,
"webhostranking.com/images/bluehost-coupon-banner-1.gif": null,
"forms.aweber.com/form/styled_popovers_and_lightboxes.js": null,
"vodo.net/static/images/promotion/utorrent_plus_buy.png": null,
"liveonlinetv247.com/images/muvixx-150x50-watch-now-in-hd-play-btn.gif": null,
"wheninmanila.com/wp-content/uploads/2014/02/DTC-Hardcore-Quadcore-300x100.gif": null,
"zylom.com/pixel.jsp": null,
"aeroplan.com/static/js/omniture/s_code_prod.js": null,
"military.com/data/popup/new_education_popunder.htm": null,
"watchuseek.com/site/forabar/zixenflashwatch.swf": null,
"cloudfront.net/scripts/cookies.js": null,
"naptol.com/usr/local/csp/staticContent/js/ga.js": null,
"adap.tv/redir/client/static/as3adplayer.swf": null,
"dl-protect.com/pop.js": null,
"csmonitor.com/extension/csm_base/design/standard/javascript/adobe/s_code.js": null,
"crabcut.net/popup.js": null,
"ragezone.com/wp-content/uploads/2019/02/Widget_HF.png": null,
"sexier.com/services/adsredirect.ashx": null,
"skyrock.net/js/stats_blog.js": null,
"wheninmanila.com/wp-content/uploads/2011/05/Benchmark-Email-Free-Signup.gif": null,
"privacytool.org/AnonymityChecker/js/fontdetect.js": null,
"bongacash.com/tools/promo.php": null,
"paypal.com/acquisition-app/static/js/s_code.js": null,
"aircanada.com/shared/common/sitecatalyst/s_code.js": null,
"ulogin.ru/js/stats.js": null,
"soe.com/js/web-platform/web-data-tracker.js": null,
"audiusa.com/us/brand/en.usertracking_javascript.js": null,
"csmonitor.com/extension/csm_base/design/csm_design/javascript/omniture/s_code.js": null,
"amazonaws.com/pmb-musics/download_itunes.png": null,
"fncstatic.com/static/all/js/geo.js": null,
"wheninmanila.com/wp-content/uploads/2014/04/zion-wifi-social-hotspot-system.png": null,
"shopping.com/sc/pac/sdc_widget_v2.0_proxy.js": null,
"wired.com/tracker.js": null,
"ragezone.com/wp-content/uploads/2019/02/chawk.jpg": null,
"careerwebsite.com/distrib_pages/jobs.cfm": null,
"androidfilehost.com/libs/otf/stats.otf.php": null,
"hotdeals360.com/static/js/kpwidgetweb.js": null,
"watchop.com/player/watchonepiece-gao-gamebox.swf": null,
"quintcareers.4jobs.com/Common/JavaScript/functions.tracking.js": null,
"addtoany.com/menu/transparent.gif": null,
"btkitty.org/static/images/880X60.gif": null,
"johnbridge.com/vbulletin/images/tyw/cdlogo-john-bridge.jpg": null,
"libertyblitzkrieg.com/wp-content/uploads/2012/09/cc200x300.gif": null,
"watchuseek.com/media/longines_legenddiver.gif": null,
"thumblogger.com/thumblog/top_banner_silver.js": null,
"cams.com/p/cams/cpcs/streaminfo.cgi": null,
"healthcarejobsite.com/Common/JavaScript/functions.tracking.js": null,
"razor.tv/site/servlet/tracker.jsp": null,
"downloadsmais.com/imagens/download-direto.gif": null,
"investegate.co.uk/Weblogs/IGLog.aspx": null,
"sexvideogif.com/msn.js": null,
"fileplanet.com/fileblog/sub-no-ad.shtml": null,
"whatreallyhappened.com/webpageimages/banners/uwslogosm.jpg": null,
"ebizmbainc.netdna-cdn.com/images/tab_sponsors.gif": null,
"attorrents.com/static/images/download3.png": null,
"webtutoriaux.com/services/compteur-visiteurs/index.php": null,
"technewsdaily.com/crime-stats/local_crime_stats.php": null,
"cruisesalefinder.co.nz/affiliates.html": null,
"ibtimes.com/player/stats.swf": null,
"picturevip.com/imagehost/top_banners.html": null,
"cdnplanet.com/static/rum/rum.js": null,
"nbcudigitaladops.com/hosted/housepix.gif": null,
"statig.com.br/pub/setCookie.js": null,
"washingtonpost.com/wp-srv/javascript/piggy-back-on-ads.js": null,
"lexus.com/lexus-share/js/campaign_tracking.js": null,
"washtimes.com/static/images/SelectAutoWeather_v2.gif": null,
"swatchseries.to/bootstrap.min.js": null,
"better-explorer.com/wp-content/uploads/2012/09/credits.png": null,
"btkitty.com/static/images/880X60.gif": null,
"google-analytics.com/siteopt.js": null,
"klm.com/travel/generic/static/js/measure_async.js": null,
"domainapps.com/assets/img/domain-apps.gif": null,
"vidyoda.com/fambaa/chnls/ADSgmts.ashx": null,
"ino.com/img/sites/mkt/click.gif": null,
"shareit.com/affiliate.html": null,
"qbn.com/media/static/js/ga.js": null,
"jillianmichaels.com/images/publicsite/advertisingslug.gif": null,
"youwatch.org/vod-str.html": null,
"static.pes-serbia.com/prijatelji/zero.png": null,
"desiretoinspire.net/storage/layout/royalcountessad.gif": null,
"cardstore.com/affiliate.jsp": null,
"sexilation.com/wp-content/uploads/2013/01/Untitled-1.jpg": null,
"staticice.com.au/cgi-bin/stats.cgi": null,
"ewrc-results.com/images/horni_ewrc_result_banner3.jpg": null,
"kitco.com/ssi/dmg_banner_001.stm": null,
"meanjin.com.au/static/images/sponsors.jpg": null,
"xbox-scene.com/crave/logo_on_white_s160.jpg": null,
"watchuseek.com/media/clerc-final.jpg": null,
"google-analytics.com/cx/api.js": null,
"worldnow.com/global/tools/video/Namespace_VideoReporting_DW.js": null,
"friday-ad.co.uk/endeca/afccontainer.aspx": null,
"go4up.com/assets/img/download-button.png": null,
"playstation.com/pscomauth/groups/public/documents/webasset/community_secured_s_code.js": null,
"jappy.tv/i/wrbng/abb.png": null,
"messianictimes.com/images/Jews%20for%20Jesus%20Banner.png": null,
"ablacrack.com/popup-pvd.js": null,
"watchseries.eu/images/affiliate_buzz.gif": null,
"lijit.com/adif_px.php": null,
"greyorgray.com/images/Fast%20Business%20Loans%20Ad.jpg": null,
"streams.tv/js/slidingbanner.js": null,
"virginholidays.co.uk/_assets/js/dc_storm/track.js": null,
"sofascore.com/geoip.js": null,
"lightboxcdn.com/static/identity.html": null,
"mnginteractive.com/live/js/omniture/SiteCatalystCode_H_22_1_NC.js": null,
"livetradingnews.com/wp-content/uploads/vamp_cigarettes.png": null,
"cloudfront.net/track.html": null,
"ibrod.tv/ib.php": null,
"atom-data.io/session/latest/track.html": null,
"24hourfitness.com/includes/script/siteTracking.js": null,
"webmd.com/dtmcms/live/webmd/PageBuilder_Assets/JS/oas35.js": null,
"nih.gov/medlineplus/images/mplus_en_survey.js": null,
"arstechnica.com/dragons/breath.gif": null,
"russellgrant.com/hostedsearch/panelcounter.aspx": null,
"expressen.se/static/scripts/s_code.js": null,
"zipcode.org/site_images/flash/zip_v.swf": null,
"myanimelist.net/static/logging.html": null,
"redtube.com/js/track.js": null,
"momtastic.com/libraries/pebblebed/js/pb.track.js": null,
"devilgirls.co/images/devil.gif": null,
"youwatch.org/driba.html": null,
"youwatch.org/9elawi.html": null,
"youwatch.org/iframe1.html": null,
"playomat.de/sfye_noscript.php": null,
"fileom.com/img/downloadnow.png": null,
"as.jivox.com/jivox/serverapis/getcampaignbysite.php": null,
"microsoft.com/getsilverlight/scripts/silverlight/SilverlightAtlas-MSCOM-Tracking.js": null,
"v.blog.sohu.com/dostat.do": null,
"cafenews.pl/mpl/static/static.js": null,
"better-explorer.com/wp-content/uploads/2013/07/hf.5.png": null,
"serial.sw.cracks.me.uk/img/logo.gif": null,
"windows.net/script/p.js": null,
"skyrock.net/img/pix.gif": null,
"makeagif.com/parts/fiframe.php": null,
"monkeyquest.com/monkeyquest/static/js/ga.js": null,
"cclickvidservgs.com/mattel/cclick.js": null,
"scientopia.org/public_html/clr_lympholyte_banner.gif": null,
"imgdino.com/gsmpop.js": null,
"nih.gov/share/scripts/survey.js": null,
"letour.fr/img/v6/sprite_partners_2x.png": null,
"twitvid.com/mediaplayer/players/tracker.swf": null,
"watchuseek.com/media/wus-image.jpg": null,
"syndication.visualthesaurus.com/std/vtad.js": null,
"scriptlance.com/cgi-bin/freelancers/ref_click.cgi": null,
"desiretoinspire.net/storage/layout/modmaxbanner.gif": null,
"lazygirls.info/click.php": null,
"mywot.net/files/wotcert/vipre.png": null,
"gold-prices.biz/gold_trading_leader.gif": null,
"cdn.cdncomputer.com/js/main.js": null,
"pubarticles.com/add_hits_by_user_click.php": null,
"xcams.com/livecams/pub_collante/script.php": null,
"international-property.countrylife.co.uk/js/search_widget.js": null,
"alladultnetwork.tv/main/videoadroll.xml": null,
"prospects.ac.uk/assets/js/prospectsWebTrends.js": null,
"images.military.com/pixel.gif": null,
"englishgrammar.org/images/30off-coupon.png": null,
"celebstoner.com/assets/images/img/top/420VapeJuice960x90V3.gif": null };
var bad_da_hostpath_exact_flag = 200 > 0 ? true : false;  // test for non-zero number of rules
    
// 200 rules as an efficient NFA RegExp:
var bad_da_hostpath_RegExp = /^(?:[\w-]+\.)*?(?:doubleclick\.net\/adx\/|doubleclick\.net\/adj\/|piano\-media\.com\/uid\/|jobthread\.com\/t\/|quantserve\.com\/pixel\/|pornfanplace\.com\/js\/pops\.|doubleclick\.net\/pixel|baidu\.com\/pixel|doubleclick\.net\/ad\/|netdna\-ssl\.com\/tracker\/|addthiscdn\.com\/live\/|porntube\.com\/adb\/|adf\.ly\/_|baidu\.com\/ecom|imageshack\.us\/ads\/|freakshare\.com\/banner\/|adform\.net\/banners\/|facebook\.com\/tr|widgetserver\.com\/metrics\/|adultfriendfinder\.com\/banners\/|veeseo\.com\/tracking\/|amazonaws\.com\/analytics\.|google\-analytics\.com\/plugins\/|gamerant\.com\/ads\/|barnebys\.com\/widgets\/|chaturbate\.com\/affiliates\/|redtube\.com\/stats\/|adultfriendfinder\.com\/javascript\/|view\.atdmt\.com\/partner\/|sextronix\.com\/images\/|channel4\.com\/ad\/|yahoo\.com\/track\/|yahoo\.com\/beacon\/|domaintools\.com\/partners\/|cloudfront\.net\/track|visiblemeasures\.com\/log|google\.com\/analytics\/|wupload\.com\/referral\/|4tube\.com\/iframe\/|pop6\.com\/banners\/|google\-analytics\.com\/gtm\/js|cursecdn\.com\/banner\/|dditscdn\.com\/log\/|adultfriendfinder\.com\/go\/|propelplus\.com\/track\/|wtprn\.com\/sponsors\/|github\.com\/_stats|mediaplex\.com\/ad\/js\/|photobucket\.com\/track\/|xvideos\-free\.com\/d\/|sex\.com\/popunder\/|imagetwist\.com\/banner\/|slashgear\.com\/stats\/|hothardware\.com\/stats\/|siberiantimes\.com\/counter\/|pan\.baidu\.com\/api\/analytics|pornoid\.com\/contents\/content_sources\/|healthtrader\.com\/banner\-|wired\.com\/event|broadbandgenie\.co\.uk\/widget|zawya\.com\/ads\/|appspot\.com\/stats|soufun\.com\/stats\/|video\-cdn\.abcnews\.com\/ad_|primevideo\.com\/uedata\/|xxxhdd\.com\/contents\/content_sources\/|msn\.com\/tracker\/|hstpnetwork\.com\/ads\/|fapality\.com\/contents\/content_sources\/|soundcloud\.com\/event|vodpod\.com\/stats\/|cnn\.com\/ad\-|livedoor\.com\/counter\/|shareasale\.com\/image\/|rapidgator\.net\/images\/pics\/|pornalized\.com\/contents\/content_sources\/|topbucks\.com\/popunder\/|adroll\.com\/pixel\/|conduit\.com\/\/banners\/|sourceforge\.net\/log\/|googlesyndication\.com\/sodar\/|googlesyndication\.com\/safeframe\/|youtube\.com\/ptracking|youtube\.com\/pagead\/|chameleon\.ad\/banner\/|gamestar\.de\/_misc\/tracking\/|hosting24\.com\/images\/banners\/|videoplaza\.tv\/proxy\/tracker[^\w.%-]|twitter\.com\/i\/jot|ad\.admitad\.com\/banner\/|daylogs\.com\/counter\/|sawlive\.tv\/ad|phncdn\.com\/iframe|chaturbate\.com\/creative\/|lovefilm\.com\/partners\/|sparklit\.com\/counter\/|citygridmedia\.com\/ads\/|fwmrm\.net\/ad\/|static\.criteo\.net\/js\/duplo[^\w.%-]|red\-tube\.com\/popunder\/|keepvid\.com\/ads\/|ad\.atdmt\.com\/s\/|xhamster\.com\/ads\/|spacash\.com\/popup\/|baidu\.com\/billboard\/pushlog\/|videowood\.tv\/pop2|aliexpress\.com\/js\/beacon_|static\.criteo\.net\/images[^\w.%-]|liutilities\.com\/partners\/|twitter\.com\/metrics|filecrypt\.cc\/p\.|ad\.atdmt\.com\/i\/img\/|dailymotion\.com\/track\-|dailymotion\.com\/track\/|doubleclick\.net\/activity|ad\.atdmt\.com\/e\/|doubleclick\.net\/pfadx\/video\.marketwatch\.com\/|mochiads\.com\/srv\/|ad\.admitad\.com\/fbanner\/|rt\.com\/static\/img\/banners\/|anysex\.com\/assets\/|virool\.com\/widgets\/|videoplaza\.com\/proxy\/distributor\/|drift\.com\/track|fulltiltpoker\.com\/affiliates\/|mygaming\.co\.za\/news\/wp\-content\/wallpapers\/|shareaholic\.com\/analytics_|ad\.atdmt\.com\/m\/|ad\.doubleclick\.net\/ddm\/trackclk\/|pornmaturetube\.com\/content\/|trrsf\.com\/metrics\/|livefyre\.com\/tracking\/|amazon\.com\/clog\/|questionmarket\.com\/static\/|carbiz\.in\/affiliates\-and\-partners\/|thrixxx\.com\/affiliates\/|andyhoppe\.com\/count\/|theporncore\.com\/contents\/content_sources\/|reevoo\.com\/track\/|cdn77\.org\/tags\/|wishlistproducts\.com\/affiliatetools\/|banners\.friday\-ad\.co\.uk\/hpbanneruploads\/|bristolairport\.co\.uk\/~\/media\/images\/brs\/blocks\/internal\-promo\-block\-300x250\/|techkeels\.com\/creatives\/|google\-analytics\.com\/collect|powvideo\.net\/ban\/|sydneyolympicfc\.com\/admin\/media_manager\/media\/mm_magic_display\/|tlavideo\.com\/affiliates\/|singlehop\.com\/affiliates\/|amazonaws\.com\/bo\-assets\/production\/banner_attachments\/|ad\.mo\.doubleclick\.net\/dartproxy\/|hulkload\.com\/b\/|mrc\.org\/sites\/default\/files\/uploads\/images\/Collusion_Banner|static\.criteo\.com\/images[^\w.%-]|akamai\.net\/chartbeat\.|sitegiant\.my\/affiliate\/|amazonaws\.com\/publishflow\/|jdoqocy\.com\/image\-|tkqlhce\.com\/image\-|kqzyfj\.com\/image\-|bluehost\-cdn\.com\/media\/partner\/images\/|express\.de\/analytics\/|ebaystatic\.com\/aw\/signin\/ebay\-signin\-toyota\-|amazonaws\.com\/ownlocal\-|betwaypartners\.com\/affiliate_media\/|supplyframe\.com\/partner\/|femalefirst\.co\.uk\/widgets\/|sulia\.com\/papi\/sulia_partner\.js\/|howtogermany\.com\/banner\/|allanalpass\.com\/track\/|phncdn\.com\/images\/banners\/|doubleclick\.net\/pfadx\/mc\.channelnewsasia\.com[^\w.%-]|static\.twincdn\.com\/special\/script\.packed|doubleclick\.net\/pfadx\/tmz\.video\.wb\.dart\/|bigrock\.in\/affiliate\/|doubleclick\.net\/pfadx\/intl\.sps\.com\/|doubleclick\.net\/pfadx\/www\.tv3\.co\.nz|share\-online\.biz\/affiliate\/|plugins\.longtailvideo\.com\/yourlytics|doubleclick\.net\/pfadx\/ctv\.ctvwatch\.ca\/|metromedia\.co\.za\/bannersys\/banners\/|mtvnservices\.com\/metrics\/|doubleclick\.net\/pfadx\/nbcu\.nhl\.|doubleclick\.net\/pfadx\/nbcu\.nhl\/|obox\-design\.com\/affiliate\-banners\/|doubleclick\.net\/pfadx\/ugo\.gv\.1up\/|goldmoney\.com\/~\/media\/Images\/Banners\/|storage\.to\/affiliate\/|vidzi\.tv\/mp4|doubleclick\.net\/pfadx\/ndm\.tcm\/|doubleclick\.net\/pfadx\/bzj\.bizjournals\/|bruteforcesocialmedia\.com\/affiliates\/|sun\.com\/share\/metrics\/|flixcart\.com\/affiliate\/|infibeam\.com\/affiliate\/|lawdepot\.com\/affiliate\/|seedsman\.com\/affiliate\/|couptopia\.com\/affiliate\/|dnsstuff\.com\/dnsmedia\/images\/ft\.banner\.|groupon\.com\/tracking)/i;
var bad_da_hostpath_regex_flag = 200 > 0 ? true : false;  // test for non-zero number of rules
    
// 200 rules as an efficient NFA RegExp:
var bad_da_RegExp = /^(?:[\w-]+\.)*?(?:porntube\.com\/ads$|ads\.|adv\.|quantserve\.com\/pixel;|banners\.|banner\.|affiliate\.|affiliates\.|cloudfront\.net\/\?a=|erotikdeal\.com\/\?ref=|synad\.|torrentz2\.eu[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|yahoo\.com\/p\.gif;|bluehost\.com\/web\-hosting\/domaincheckapi\/\?affiliate=|qualtrics\.com\/WRSiteInterceptEngine\/\?Q_Impress=|ad\.atdmt\.com\/i\/go;|kickass2\.st[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|sweed\.to\/\?pid=|movies\.askjolene\.com\/c64\?clickid=|tube911\.com\/scj\/cgi\/out\.php\?scheme_id=|cloudfront\.net\/\?tid=|oddschecker\.com\/clickout\.htm\?type=takeover\-|ipornia\.com\/scj\/cgi\/out\.php\?scheme_id=|sponsorselect\.com\/Common\/LandingPage\.aspx\?eu=|api\.ticketnetwork\.com\/Events\/TopSelling\/domain=nytimes\.com|247hd\.net\/ad$|consensu\.org\/\?log=|inn\.co\.il\/Controls\/HPJS\.ashx\?act=log|affiliates2\.|katcr\.co[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|nowwatchtvlive\.ws[^\w.%-]\$csp=script\-src 'self' |torrentdownloads\.me[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|x1337x\.ws[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|eurolive\.com\/\?module=public_eurolive_onlinehostess&|totalporn\.com\/videos\/tracking\/\?url=|alibi\.com\/\?request_type=aimg|readlightnovel\.org[^\w.%-]\$csp=script\-src 'self' |eurolive\.com\/index\.php\?module=public_eurolive_onlinetool&|plista\.com\/async\/min\/video,outstream\/|rehost\.to\/\?ref=|bufferapp\.com\/wf\/open\?upn=|doubleclick\.net\/imp;|ab\-in\-den\-urlaub\.de\/resources\/cjs\/\?f=\/resources\/cjs\/tracking\/|amazonaws\.com\/\?wsid=|kommersant\.ru\/a\.asp\?p=|augine\.com\/widget$|seatplans\.com\/widget$|thisgengaming\.com\/Scripts\/widget2\.aspx\?id=|mail\.yahoo\.com\/neo\/mbimg\?av\/curveball\/ds\/|comicgenesis\.com\/tcontent\.php\?out=|urmediazone\.com\/play\?ref=|irs01\.|vpnfortorrents\.org\/\?id=|yahoo\.com\/yi\?bv=|gameknot\.com\/amaster\.pl\?j=|yourbittorrent2\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|ok\.ru\/dk\?cmd=videoStatNew|fancybar\.net\/ac\/fancybar\.js\?zoneid|jewsnews\.co\.il[^\w.%-]\$csp=script\-src 'self' |uploadproper\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|watchsomuch\.info[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|tvcommunity\.at\/filmpicture\.aspx\?count=1&|hyperlinksecure\.com\/back\?token=|bittorrent\.am[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|uploadproper\.net[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|downsub\.com[^\w.%-]\$csp=script\-src 'self' |x1337x\.se[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|madmimi\.com\/view\?id=|freelotto\.com\/offer\.asp\?offer=|musicstack\.com\/livezilla\/server\.php\?request=track|limetorrents\.info[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|s5labs\.io\/common\/i\?impressionId|torrentfunk2\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|pirateiro\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|magnetdl\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|torlock\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|juno\.com\/start\/javascript\.do\?message=|fleshlight\.com\/\?link=|plista\.com\/jsmodule\/flash$|stargames\.com\/bridge\.asp\?idr=|redtube\.com\/blockcount$|yahoo\.com\/serv\?s|camcity\.com\/rtr\.php\?aid=|k7\-labelgroup\.com\/g\.html\?uid=|yahoo\.co\.jp\/b\?p=|fileshut\.com\/etc\/links\.php\?q=|download\-provider\.org\/\?aff\.id=|24ur\.com\/bin\/player\/\?mod=statistics&|antonymsfor\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' http\: https\:|videobox\.com\/\?tid=|seedpeer\.me[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|oneload\.site[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|moosify\.com\/widgets\/explorer\/\?partner=|mail\.yahoo\.com\/dc\/rs\?log=|nativly\.com\/tds\/widget\?wid=|netreviews\.eu\/index\.php\?action=act_access&|monova\.to[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|ooyala\.com\/authorized\?analytics|bloomberg\.com\/apps\/data\?referrer|myfreecams\.com\/\?co_id=|x1337x\.eu[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|stripe\.com\/\?event=|retrevo\.com\/m\/google\?q=|heroku\.com\/\?callback=getip|wikimedia\.org\/wiki\/Special\:RecordImpression\?|babylon\.com\/welcome\/index\.html\?affID=|xvideoslive\.com\/\?AFNO|exmo\.me\/\?ref=|xhamster\.com\/ajax\.php\?act=track_event|6angebot\.ch\/\?ref=|monova\.org[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|ebayrtm\.com\/rtm\?RtmCmd&a=img&|torrentdownload\.ch[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|6waves\.com\/edm\.php\?uid=|moonb\.ch\/\?ref=|exposedwebcams\.com\/\?token=|linkbucks\.com\/clean\.aspx\?task=record|vkpass\.com\/goo\.php\?link=|overstock\.com\/dlp\?cci=|elb\.amazonaws\.com\/\?page=|777livecams\.com\/\?id=|expertreviews\.co\.uk\/\?act=widgets\.|24option\.com\/\?oftc=|sweeva\.com\/widget\.php\?w=|edomz\.com\/re\.php\?mid=|anvato\.com\/anvatoloader\.swf\?analytics=|pinkvisualgames\.com\/\?revid=|id\.verticalhealth\.net\/script\.js\?partnerid=|xrounds\.com\/\?lmid=|manhunt\.net\/\?dm=|etwun\.com\:8080\/counter\.php\?|eztv\.io[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|serving\-sys\.com\/Serving\?cn=display&|imdb\.com\/rd\/\?q|ebayrtm\.com\/rtm\?RtmIt|yahoo\.co\.jp\/s\?s=|p\.po\.st\/p\?t=view&|yahoo\.com\/sig=|1337x\.st[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|photographyblog\.com\/\?ACT|freeones\.com\/cd\/\?cookies=|redlightcenter\.com\/\?trq=|dictionary\.cambridge\.org\/info\/frame\.html\?zone=|usage\.zattoo\.com\/\?adblock=|1337x\.to[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|d2kbaqwa2nt57l\.cloudfront\.net\/\?qabkd=|grammarly\.com\/embedded\?aff=|msn\.com\/\?adunitid|my\-dirty\-hobby\.com\/\?sub=|ebay\.com\/op\/t\.do\?event|pop\-over\.|elb\.amazonaws\.com\/g\.aspx\?surl=|aliexpress\.com\/\?af=|gamezone\.com\/\?act=|ip\-adress\.com\/gl\?r=|liverail\.com\/\?metric=|theselfdefenseco\.com\/\?affid=|akamaized\.net\/\?u=|sugarops\.com\/w\?action=impression|imagetwist\.com\/\?op=|api\.tinypic\.com\/api\.php\?action=track|fulltiltpoker\.com\/\?key=|jpost\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' http\: https\: blob\:|cursecdn\.com\/shared\-assets\/current\/anchor\.js\?id=|cloudfront\.net\/i\?stm=|promo\.|dditscdn\.com\/\?a=|freakshare\.com\/\?ref=|piwik\.|tinypic\.com\/api\.php\?(?=([\s\S]*?&action=track))\1|t\-online\.de[^\w.%-](?=([\s\S]*?\/stats\.js\?track=))\2|photobucket\.com[^\w.%-](?=([\s\S]*?\/api\.php\?))\3(?=([\s\S]*?&method=track&))\4|t\-online\.de[^\w.%-](?=([\s\S]*?\/noresult\.js\?track=))\5|truste\.com\/notice\?(?=([\s\S]*?consent\-track))\6|sim\-technik\.de[^\w.%-](?=([\s\S]*?&uniqueTrackId=))\7|bild\.de\/code\/linktracking,(?=([\s\S]*?\.js))\8|ws\.amazon\.com\/widgets\/(?=([\s\S]*?=gettrackingid$))\9|videosz\.com[^\w.%-](?=([\s\S]*?&tracker_id=))\10|secureprovide1\.com\/(?=([\s\S]*?=tracking))\11|etahub\.com[^\w.%-](?=([\s\S]*?\/track\?site_id))\12|casino\-x\.com[^\w.%-](?=([\s\S]*?\?partner=))\13|fantasti\.cc[^\w.%-](?=([\s\S]*?\?ad=))\14|quantserve\.com[^\w.%-](?=([\s\S]*?[^\w.%-]a=))\15|blacklistednews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\16|swatchseries\.to[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\17|ad\.atdmt\.com\/i\/(?=([\s\S]*?=))\18|allmyvideos\.net\/(?=([\s\S]*?=))\19|thevideo\.me\/(?=([\s\S]*?\:))\20|2hot4fb\.com\/img\/(?=([\s\S]*?\.gif\?r=))\21|iyfsearch\.com[^\w.%-](?=([\s\S]*?&pid=))\22|4chan\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline' ))\23(?=([\s\S]*?\.gstatic\.com ))\24(?=([\s\S]*?\.google\.com ))\25(?=([\s\S]*?\.googleapis\.com ))\26(?=([\s\S]*?\.4cdn\.org ))\27(?=([\s\S]*?\.4channel\.org))\28|flirt4free\.com[^\w.%-](?=([\s\S]*?&utm_campaign))\29|get\.(?=([\s\S]*?\.website\/static\/get\-js\?stid=))\30|media\.campartner\.com\/index\.php\?cpID=(?=([\s\S]*?&cpMID=))\31|plista\.com\/widgetdata\.php\?(?=([\s\S]*?%22pictureads%22%7D))\32|1movies\.is[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' 'unsafe\-eval' data\: (?=([\s\S]*?\.jwpcdn\.com ))\33(?=([\s\S]*?\.gstatic\.com ))\34(?=([\s\S]*?\.googletagmanager\.com ))\35(?=([\s\S]*?\.addthis\.com ))\36(?=([\s\S]*?\.google\.com))\37|watchcartoononline\.io[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\38|freehostedscripts\.net[^\w.%-](?=([\s\S]*?\.php\?site=))\39(?=([\s\S]*?&s=))\40(?=([\s\S]*?&h=))\41|btkitty\.pet[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' (?=([\s\S]*?\.cloudflare\.com ))\42(?=([\s\S]*?\.googleapis\.com ))\43(?=([\s\S]*?\.jsdelivr\.net))\44|facebook\.com\/(?=([\s\S]*?\/plugins\/send_to_messenger\.php\?app_id=))\45)/i;
var bad_da_regex_flag = 200 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_url_parts_RegExp = /^$/;
var good_url_parts_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 200 rules as an efficient NFA RegExp:
var bad_url_parts_RegExp = /(?:\/adcontent\.|\/adsys\/|\/adserver\.|\.com\/ads\?|\/pp\-ad\.|\?getad=&|\/img\/adv\.|\/img\/adv\/|\/expandable_ad\?|\.online\/ads\/|\/online\/ads\/|\/ad\-engine\.|\/ad_engine\?|\-web\-ad\-|\/web\-ad_|\/imgad\.|\/imgad\?|\/iframead\.|\/iframead\/|\/contentad\/|\/contentad$|\-leaderboard\-ad\-|\/leaderboard_ad\.|\/leaderboard_ad\/|\-ad\-content\/|\/ad\/content\/|\/ad_content\.|\/adcontent\/|\/ad\-images\/|\/ad\/images\/|\/ad_images\/|\/ad\-image\.|\/ad\/image\/|\/ad_image\.|\/homepage\-ads\/|\/homepage\/ads\/|\/webad\?|_webad\.|\/adplugin\.|\/adplugin\/|\/adplugin_|\-content\-ad\-|\-content\-ad\.|\/content\/ad\/|\/content\/ad_|\/content_ad\.|_content_ad\.|\-iframe\-ad\.|\/iframe\-ad\.|\/iframe\-ad\/|\/iframe\-ad\?|\/iframe\.ad\/|\/iframe\/ad\/|\/iframe\/ad_|\/iframe_ad\.|\/iframe_ad\?|\/static\/tracking\/|\/video\-ad\.|\/video\/ad\/|\/video_ad\.|\.com\/video\-ad\-|\-ad_leaderboard\/|\/ad\-leaderboard\.|\/ad\/leaderboard\.|\/ad_leaderboard\.|\/ad_leaderboard\/|=ad\-leaderboard\-|\/_img\/ad_|\/img\/_ad\.|\/img\/ad\-|\/img\/ad\.|\/img\/ad\/|\/img_ad\/|\/assets\/js\/ad\.|\/superads_|_js\/ads\.js|\/t\/event\.js\?|\/web\-analytics\.|\/web_analytics\/|=adcenter&|\-ad\-iframe\.|\-ad\-iframe\/|\-ad\/iframe\/|\/ad\-iframe\-|\/ad\-iframe\.|\/ad\-iframe\?|\/ad\/iframe\.|\/ad\/iframe\/|\/ad\?iframe_|\/ad_iframe\.|\/ad_iframe_|=ad_iframe&|=ad_iframe_|\/pop2\.js$|\.adriver\.|\/adriver\.|\/adriver_|\/media\/ad\/|\/xtclicks\.|\/xtclicks_|\/bottom\-ads\.|\.com\/\?adv=|\/post\/ads\/|\/expandable_ad\.php|\/popad$|\/bg\/ads\/|_search\/ads\.js|\-top\-ads\.|\/top\-ads\.|\-text\-ads\.|\-show\-ads\.|\/show\-ads\.|\/footer\-ads\/|\.net\/ad\/|\/ad\?count=|\/ad_count\.|\/mobile\-ads\/|\-iframe\-ads\/|\/iframe\-ads\/|\/iframe\/ads\/|\-ads\-iframe\.|\/ads\/iframe|\/ads_iframe\.|\/ad\/logo\/|\/special\-ads\/|\/ad\.php$|\/modules\/ads\/|\-article\-ads\-|\/dynamic\/ads\/|_track\/ad\/|\/afs\/ads\/|\/player\/ads\.|\/player\/ads\/|\-video\-ads\/|\/video\-ads\/|\/video\.ads\.|\/video\/ads\/|\.no\/ads\/|\/i\/ads\/|\/ad\?sponsor=|\/vast\/ads\-|\/js\/ads\-|\/js\/ads\.|\/js\/ads_|\/mini\-ads\/|\/ads\/html\/|\/user\/ads\?|\/house\-ads\/|\/inc\/ads\/|\/pc\/ads\.|\/cms\/ads\/|\/external\/ads\/|\/ads\.cms|\/ads12\.|\-adskin\.|\/adskin\/|\/adsetup\.|\/adsetup_|\/adsframe\.|\/ext\/ads\/|\/adsdaq_|\/responsive\-ads\.|\/td\-ads\-|\/delivery\.ads\.|\/ad132m\/|\/blogad\.|\/adbanners\/|\/custom\/ads|\/default\/ads\/|\/remove\-ads\.|\/banner\-adv\-|\/banner\/adv\/|\/banner\/adv_|\/sidebar\-ads\/|\/ads_reporting\/|\/left\-ads\.|\-online\-advert\.|\/ads\/async\/|\/ads\/targeting\.|\/adclick\.|\/adlog\.|\/adsrv\.|\/adsrv\/|\/sponsored_ad\.|\/sponsored_ad\/|\.co\/ads\/|\/log\/ad\-|\/log_ad\?|\/adsys\.|\/analytics\.gif\?|\.ads\.css|\/ads\.css|\/image\/ads\/|\/image\/ads_|\/pagead\/conversion_|\/pagead\/conversion\.|\/pagead\/conversion\/|\/showads\/|\-peel\-ads\-|\/partner\.ads\.)/i;
var bad_url_parts_flag = 200 > 0 ? true : false;  // test for non-zero number of rules
    
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
   shExpMatch(host, "192.168.*") ||
   shExpMatch(host, "127.*") ||
   (url.substring(0,4) == "ftp:")
)
        return "DIRECT";
else
        return EasyListFindProxyForURL(url, host);
}   
