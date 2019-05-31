// PAC (Proxy Auto Configuration) Filter from EasyList rules
// 
// Copyright (C) 2017 by Steven T. Smith <steve dot t dot smith at gmail dot com>, GPL
// https://github.com/essandess/easylist-pac-privoxy/
//
// PAC file created on Fri, 31 May 2019 20:44:00 GMT
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

// 1239 rules:
var bad_da_host_JSON = { "content.ad": null,
"webvisor.ru": null,
"exoclick.com": null,
"nastydollars.com": null,
"adziff.com": null,
"tsyndicate.com": null,
"amazon-adsystem.com": null,
"sharethrough.com": null,
"dianomi.com": null,
"ad.doubleclick.net": null,
"moatads.com": null,
"adsafeprotected.com": null,
"2mdn.net": null,
"doubleclick.net": null,
"pagead2.googlesyndication.com": null,
"go.megabanners.cf": null,
"ltassrv.com.s3.amazonaws.com": null,
"adchemy-content.com": null,
"admitad.com": null,
"serving-sys.com": null,
"g00.msn.com": null,
"coinad.com": null,
"adap.tv": null,
"ip-adress.com": null,
"dashad.io": null,
"click.aliexpress.com": null,
"adult.xyz": null,
"optimizely.com": null,
"scorecardresearch.com": null,
"contentspread.net": null,
"media.net": null,
"advertising.com": null,
"chartbeat.com": null,
"static.parsely.com": null,
"teads.tv": null,
"log.pinterest.com": null,
"adnxs.com": null,
"webtrekk.net": null,
"nuggad.net": null,
"smartadserver.com": null,
"imasdk.googleapis.com": null,
"d11a2fzhgzqe7i.cloudfront.net": null,
"movad.net": null,
"flashtalking.com": null,
"rlcdn.com": null,
"mxcdn.net": null,
"stroeerdigitalmedia.de": null,
"krxd.net": null,
"clicktale.net": null,
"adverserve.net": null,
"visualwebsiteoptimizer.com": null,
"intelliad.de": null,
"cm.g.doubleclick.net": null,
"gitcdn.pw": null,
"eclick.baidu.com": null,
"crwdcntrl.net": null,
"banners.cams.com": null,
"hotjar.com": null,
"imglnkc.com": null,
"3lift.com": null,
"adform.net": null,
"ace.advertising.com": null,
"revcontent.com": null,
"quantserve.com": null,
"adition.com": null,
"xxlargepop.com": null,
"cpx.to": null,
"mediaplex.com": null,
"ad.proxy.sh": null,
"lw2.gamecopyworld.com": null,
"bluekai.com": null,
"openx.net": null,
"adapd.com": null,
"bontent.powvideo.net": null,
"adfox.yandex.ru": null,
"bongacams.com": null,
"adx.kat.ph": null,
"traffic.focuusing.com": null,
"pixel.ad": null,
"adc.stream.moe": null,
"ad.rambler.ru": null,
"adspayformymortgage.win": null,
"adv.drtuber.com": null,
"firstclass-download.com": null,
"videoplaza.com": null,
"ebayobjects.com.au": null,
"megabanners.cf": null,
"trmnsite.com": null,
"yinmyar.xyz": null,
"nkmsite.com": null,
"pdheuryopd.loan": null,
"clickopop1000.com": null,
"money-maker-script.info": null,
"money-maker-default.info": null,
"uoldid.ru": null,
"abbp1.website": null,
"kdmkauchahynhrs.ru": null,
"freecontent.download": null,
"chartaca.com.s3.amazonaws.com": null,
"pos.baidu.com": null,
"cashbigo.com": null,
"ero-advertising.com": null,
"adlink.net": null,
"ads.yahoo.com": null,
"creativecdn.com": null,
"abbp1.science": null,
"ct.pinterest.com": null,
"bzclk.baidu.com": null,
"gsp1.baidu.com": null,
"heapanalytics.com": null,
"adup-tech.com": null,
"popads.net": null,
"getclicky.com": null,
"advertserve.com": null,
"dnn506yrbagrg.cloudfront.net": null,
"adk2.co": null,
"3wr110.xyz": null,
"log.outbrain.com": null,
"pixel.facebook.com": null,
"juicyads.com": null,
"hornymatches.com": null,
"adonweb.ru": null,
"smallseotools.com": null,
"prpops.com": null,
"onad.eu": null,
"adtrace.org": null,
"adexc.net": null,
"sexad.net": null,
"admedit.net": null,
"stats.bitgravity.com": null,
"metrics.brightcove.com": null,
"htmlhubing.xyz": null,
"adbooth.com": null,
"mobsterbird.info": null,
"explainidentifycoding.info": null,
"alternads.info": null,
"videoplaza.tv": null,
"collector.contentexchange.me": null,
"am10.ru": null,
"adk2.com": null,
"adcash.com": null,
"adexchangeprediction.com": null,
"adnetworkperformance.com": null,
"august15download.com": null,
"bentdownload.com": null,
"adultadworld.com": null,
"admngronline.com": null,
"adxpansion.com": null,
"brucelead.com": null,
"venturead.com": null,
"adjuggler.net": null,
"ad-maven.com": null,
"utarget.ru": null,
"xclicks.net": null,
"ad4game.com": null,
"adplxmd.com": null,
"adrunnr.com": null,
"adxprtz.com": null,
"ad131m.com": null,
"ad2387.com": null,
"adnium.com": null,
"adxite.com": null,
"adbma.com": null,
"adk2x.com": null,
"hpr.outbrain.com": null,
"clicksor.net": null,
"popwin.net": null,
"rapidyl.net": null,
"insta-cash.net": null,
"hd-plugin.com": null,
"contentabc.com": null,
"propellerpops.com": null,
"liveadexchanger.com": null,
"ringtonematcher.com": null,
"superadexchange.com": null,
"clicksor.com": null,
"downloadboutique.com": null,
"pubads.g.doubleclick.net": null,
"sharecash.org": null,
"bullads.net": null,
"pwrads.net": null,
"whoads.net": null,
"widget.yavli.com": null,
"click.scour.com": null,
"clickmngr.com": null,
"adblade.com": null,
"ad6media.fr": null,
"clickosmedia.com": null,
"tagcdn.com": null,
"media-servers.net": null,
"xtendmedia.com": null,
"888media.net": null,
"traffictraffickers.com": null,
"clicktripz.com": null,
"c4tracking01.com": null,
"brandreachsys.com": null,
"kissmetrics.com": null,
"tracking-rce.veeseo.com": null,
"livepromotools.com": null,
"traktrafficflow.com": null,
"perfcreatives.com": null,
"advmedialtd.com": null,
"adultadmedia.com": null,
"track.xtrasize.nl": null,
"pointclicktrack.com": null,
"onclickads.net": null,
"adglare.org": null,
"youradexchange.com": null,
"ringtonepartner.com": null,
"bettingpartners.com": null,
"adcdnx.com": null,
"statsmobi.com": null,
"360adstrack.com": null,
"trafficholder.com": null,
"trafficforce.com": null,
"yieldtraffic.com": null,
"traffichaus.com": null,
"trafficshop.com": null,
"fpctraffic2.com": null,
"toroadvertisingmedia.com": null,
"mediaseeding.com": null,
"pgmediaserve.com": null,
"waframedia5.com": null,
"wigetmedia.com": null,
"clicksvenue.com": null,
"terraclicks.com": null,
"clicksgear.com": null,
"onclickmax.com": null,
"poponclick.com": null,
"clickfuse.com": null,
"adsrv4k.com": null,
"adsurve.com": null,
"adservme.com": null,
"adsupply.com": null,
"adserverplus.com": null,
"adswizz.com": null,
"adscpm.net": null,
"hm.baidu.com": null,
"adexchangetracker.com": null,
"adsmarket.com": null,
"hipersushiads.com": null,
"epicgameads.com": null,
"affbuzzads.com": null,
"megapopads.com": null,
"down1oads.com": null,
"popmyads.com": null,
"filthads.com": null,
"padsdel.com": null,
"1phads.com": null,
"webcams.com": null,
"shareasale.com": null,
"freecontent.science": null,
"popshow.info": null,
"perfectmarket.com": null,
"freecontent.win": null,
"tubeadvertising.eu": null,
"reallifecam.com": null,
"freecontent.trade": null,
"showcase.vpsboard.com": null,
"b.photobucket.com": null,
"urlcash.net": null,
"flcounter.com": null,
"abctrack.bid": null,
"adfox.ru": null,
"advertiserurl.com": null,
"zymerget.win": null,
"addmoredynamiclinkstocontent2convert.bid": null,
"ad.smartclip.net": null,
"adrotate.se": null,
"xxxmatch.com": null,
"hodling.science": null,
"trackvoluum.com": null,
"adport.io": null,
"bestforexplmdb.com": null,
"adtgs.com": null,
"adhealers.com": null,
"admeerkat.com": null,
"flagads.net": null,
"adexchangegate.com": null,
"adexchangemachine.com": null,
"adhome.biz": null,
"adm.shinobi.jp": null,
"iwebanalyze.com": null,
"patiskcontentdelivery.info": null,
"pc.thevideo.me": null,
"adop.cc": null,
"tostega.ru": null,
"affiliate.mediatemple.net": null,
"aj1574.online": null,
"bid.run": null,
"whatismyip.win": null,
"trackmytarget.com": null,
"popcash.net": null,
"lightson.vpsboard.com": null,
"plugin.ws": null,
"topad.mobi": null,
"jshosting.science": null,
"fastclick.net": null,
"metricfast.com": null,
"adglare.net": null,
"adboost.it": null,
"histats.com": null,
"hawkeye-data-production.sciencemag.org.s3-website-us-east-1.amazonaws.com": null,
"intab.xyz": null,
"9content.com": null,
"pr-static.empflix.com": null,
"predictivadvertising.com": null,
"bestquickcontentfiles.com": null,
"showcasead.com": null,
"synthasite.net": null,
"campanja.com": null,
"popunderjs.com": null,
"hilltopads.net": null,
"jshosting.win": null,
"adright.co": null,
"core.queerclick.com": null,
"vtracker.net": null,
"nextoptim.com": null,
"affiliatesmedia.sbobet.com": null,
"stats.ibtimes.co.uk": null,
"affiliate.burn-out.tv": null,
"ozon.ru": null,
"premium.naturalnews.tv": null,
"mobtop.ru": null,
"indieclick.com": null,
"vserv.bc.cdn.bitgravity.com": null,
"ad-apac.doubleclick.net": null,
"ad-emea.doubleclick.net": null,
"cookiescript.info": null,
"s11clickmoviedownloadercom.maynemyltf.netdna-cdn.com": null,
"codeonclick.com": null,
"popunder.ru": null,
"cdnmedia.xyz": null,
"webcounter.ws": null,
"mellowads.com": null,
"stat.radar.imgsmail.ru": null,
"afimg.liveperson.com": null,
"advertise.com": null,
"webstats.com": null,
"freewheel.mtgx.tv": null,
"wmemsnhgldd.ru": null,
"tracking.moneyam.com": null,
"textad.sexsearch.com": null,
"xs.mochiads.com": null,
"googleadservices.com": null,
"sessioncam.com": null,
"count.livetv.ru": null,
"affiliatehub.skybet.com": null,
"getalinkandshare.com": null,
"adverts.itv.com": null,
"adbetclickin.pink": null,
"ams.addflow.ru": null,
"ufpcdn.com": null,
"gocp.stroeermediabrands.de": null,
"affiliate.iamplify.com": null,
"adsjudo.com": null,
"clickredirection.com": null,
"tracklab.club": null,
"vpnaffiliates.hidester.com": null,
"mytrack.pro": null,
"trackingpro.pro": null,
"onclicksuper.com": null,
"pulseonclick.com": null,
"topclickguru.com": null,
"zanox-affiliate.de": null,
"onclickmega.com": null,
"backlogtop.xyz": null,
"affiliates.spark.net": null,
"affiliates-cdn.mozilla.org": null,
"trafficbroker.com": null,
"revimedia.com": null,
"trafficstars.com": null,
"topbinaryaffiliates.ck-cdn.com": null,
"nextlandingads.com": null,
"33traffic.com": null,
"mtrack.nl": null,
"video.oms.eu": null,
"affiliates.genealogybank.com": null,
"adn.ebay.com": null,
"ad.reachlocal.com": null,
"performancetrack.info": null,
"bonzai.ad": null,
"ingame.ad": null,
"spider.ad": null,
"ubertracking.info": null,
"mobitracker.info": null,
"pixel.reddit.com": null,
"dstrack2.info": null,
"trackbar.info": null,
"cache.worldfriends.tv": null,
"cpaevent.ru": null,
"pix.speedbit.com": null,
"taeadsnmbbkvpw.bid": null,
"analytics.us.archive.org": null,
"affiliates.mozy.com": null,
"affiliates.mgmmirage.com": null,
"affiliates.goodvibes.com": null,
"affiliates.swappernet.com": null,
"video-ad-stats.googlesyndication.com": null,
"bannerexchange.com.au": null,
"cloudset.xyz": null,
"affiliates.treasureisland.com": null,
"affiliates.londonmarketing.com": null,
"toptracker.ru": null,
"localytics.com": null,
"affiliateprogram.keywordspy.com": null,
"ftrack.ru": null,
"googlerank.info": null,
"affiliate.mercola.com": null,
"dashbida.com": null,
"eiadsdmj.bid": null,
"cklad.xyz": null,
"analytic.pho.fm": null,
"analytics00.meride.tv": null,
"fdxstats.xyz": null,
"fan.twitch.tv": null,
"premiumstats.xyz": null,
"advserver.xyz": null,
"free-rewards.com-s.tv": null,
"clcknads.pro": null,
"gstaticadssl.l.google.com": null,
"beacon.ehow.com": null,
"skimresources.com": null,
"buythis.ad": null,
"youroffers.win": null,
"images.criteo.net": null,
"trackingoffer.info": null,
"adcfrthyo.tk": null,
"ad.spreaker.com": null,
"affiliates.vpn.ht": null,
"hit-pool.upscore.io": null,
"u-ad.info": null,
"cookietracker.cloudapp.net": null,
"totrack.ru": null,
"ewxssoad.bid": null,
"adfrog.info": null,
"adlinx.info": null,
"adalgo.info": null,
"adofuokjj.bid": null,
"loljuduad.bid": null,
"rqmlurpad.bid": null,
"alflying.win": null,
"flightsy.win": null,
"flightzy.win": null,
"adwalte.info": null,
"adplans.info": null,
"adlerbo.info": null,
"adrtgbebgd.bid": null,
"scvonjdwad.bid": null,
"timonnbfad.bid": null,
"adm-vids.info": null,
"adproper.info": null,
"advsense.info": null,
"torads.me": null,
"ininmacerad.pro": null,
"admo.tv": null,
"adne.tv": null,
"link.link.ru": null,
"advertisingvalue.info": null,
"affiliate.resellerclub.com": null,
"adserved.net": null,
"cdnaz.win": null,
"deliberatelyvirtuallyshared.xyz": null,
"torads.xyz": null,
"bannerbank.ru": null,
"gan.doubleclick.net": null,
"ad001.ru": null,
"speee-ad.akamaized.net": null,
"advertur.ru": null,
"advombat.ru": null,
"adsnative.com": null,
"analyticapi.pho.fm": null,
"advertone.ru": null,
"chinagrad.ru": null,
"arpelog.info": null,
"ads.cc": null,
"engine.gamerati.net": null,
"advmaker.su": null,
"awstrack.me": null,
"volgograd-info.ru": null,
"partner.googleadservices.com": null,
"static.kinghost.com": null,
"vologda-info.ru": null,
"admaster.net": null,
"analytics.blue": null,
"sniperlog.ru": null,
"optimize-stats.voxmedia.com": null,
"clickpartoffon.xyz": null,
"analytics.163.com": null,
"hostingcloud.loan": null,
"adzjzewsma.cf": null,
"rlogoro.ru": null,
"tkn.4tube.com": null,
"tracker.azet.sk": null,
"microad.net": null,
"adlog.com.com": null,
"realclick.co.kr": null,
"hotlog.ru": null,
"warlog.ru": null,
"analytics.ettoredelnegro.pro": null,
"publicidad.net": null,
"blogscash.info": null,
"logxp.ru": null,
"eads.to": null,
"hostingcloud.racing": null,
"img.bluehost.com": null,
"iperceptions.com": null,
"tracker.revip.info": null,
"tracking.hostgator.com": null,
"clicktalecdn.sslcs.cdngc.net": null,
"szzxtanwoptm.bid": null,
"logz.ru": null,
"adlure.biz": null,
"analytic.rocks": null,
"nimiq.watch": null,
"access-analyze.org": null,
"nicoad.nicovideo.jp": null,
"trackword.net": null,
"moevideo.net": null,
"analytics.plex.tv": null,
"analytics.ifood.tv": null,
"trackingoffer.net": null,
"tracking.vengovision.ru": null,
"adz.zwee.ly": null,
"tracker2kss.eu": null,
"trackerodss.eu": null,
"lead.im": null,
"host-go.info": null,
"affiliate.com": null,
"hostip.info": null,
"playerassets.info": null,
"promotiontrack.mobi": null,
"analytics.carambatv.ru": null,
"screencapturewidget.aebn.net": null,
"zoomanalytics.co": null,
"aimatch.com": null,
"affiliates.lynda.com": null,
"profile.bharatmatrimony.com": null,
"stats.qmerce.com": null,
"post.rmbn.ru": null,
"fasttracktech.biz": null,
"tracker.tiu.ru": null,
"analytics.live.com": null,
"affiliates.minglematch.com": null,
"affiliates.picaboocorp.com": null,
"visitor-analytics.net": null,
"freetracker.biz": null,
"affiliates.franchisegator.com": null,
"cfcdist.loan": null,
"trackpath.biz": null,
"adfill.me": null,
"adxxx.org": null,
"adnet.ru": null,
"iptrack.biz": null,
"videos.oms.eu": null,
"adpath.mobi": null,
"leadad.mobi": null,
"analytics.wildtangent.com": null,
"adwired.mobi": null,
"quantumws.net": null,
"hostingcloud.review": null,
"jqwww.download": null,
"hello.staticstuff.net": null,
"an.yandex.ru": null,
"performanceanalyser.net": null,
"simpleanalytics.io": null,
"softonic-analytics.net": null,
"analytics-engine.net": null,
"bb-analytics.jp": null,
"owlanalytics.io": null,
"scoutanalytics.net": null,
"adbit.biz": null,
"metartmoney.met-art.com": null,
"hs-analytics.net": null,
"jquery-uim.download": null,
"sageanalyst.net": null,
"analyticsip.net": null,
"analytics-cms.whitebeard.me": null,
"userlog.synapseip.tv": null,
"monova.site": null,
"track.cooster.ru": null,
"bridgetrack.com": null,
"pleasedontslaymy.download": null,
"affiliates.myfax.com": null,
"adten.eu": null,
"visitor-analytics.io": null,
"hostingcloud.bid": null,
"adnext.org": null,
"hostingcloud.faith": null,
"event.getblue.io": null,
"ad-vice.biz": null,
"track.revolvermarketing.ru": null,
"addynamics.eu": null,
"analytics.wetpaint.me": null,
"ker.pic2pic.site": null,
"huluads.info": null,
"ad.spielothek.so": null,
"affiliate.godaddy.com": null,
"counter.webmasters.bpath.com": null,
"analytic.piri.net": null,
"analoganalytics.com": null,
"adregain.ru": null,
"analytics.styria.hr": null,
"cdnfile.xyz": null,
"adultsense.org": null,
"ad2adnetwork.biz": null,
"cpufan.club": null,
"spinbox.freedom.com": null,
"n4403ad.doubleclick.net": null,
"ad.gt": null,
"sabin.free.fr": null,
"webts.adac.de": null,
"adserve.ph": null,
"brandads.net": null,
"xvideosharing.site": null,
"xfast.host": null,
"affiliates.galapartners.co.uk": null,
"log.worldsoft-cms.info": null,
"log.ren.tv": null,
"optimalroi.info": null,
"smartoffer.site": null,
"yandex-metrica.ru": null,
"pixel.xmladfeed.com": null,
"monkeytracker.cz": null,
"socialtrack.co": null,
"filadmir.site": null,
"gctwh9xc.site": null,
"itempana.site": null,
"jfx61qca.site": null,
"less-css.site": null,
"1wzfew7a.site": null,
"ag2hqdyt.site": null,
"dom002.site": null,
"adaction.se": null,
"xtracker.pro": null,
"socialtrack.net": null,
"analytics.gvim.mobi": null,
"relead.com": null,
"i2ad.jp": null,
"advg.jp": null,
"tjblfqwtdatag.bid": null,
"adxxx.me": null,
"track.ultimate-guitar.com": null,
"analytics.proxer.me": null,
"stattds.club": null,
"adregain.com": null,
"adinte.jp": null,
"aid-ad.jp": null,
"adnico.jp": null,
"googleme.eu": null,
"powerad.ai": null,
"redirections.site": null,
"affiliates.thrixxx.com": null,
"internalredirect.site": null,
"content-offer-app.site": null,
"infinity-tracking.net": null,
"trackstarsengland.net": null,
"accede.site": null,
"traffic-media.co.uk": null,
"trackadvertising.net": null,
"getscorecash.com": null,
"vihtori-analytics.fi": null,
"admatrix.jp": null,
"dm-event.net": null,
"trackdiscovery.net": null,
"trackpromotion.net": null,
"adgoi.mobi": null,
"dfanalytics.dealerfire.com": null,
"tracetracking.net": null,
"air360tracker.net": null,
"avazutracking.net": null,
"admaya.in": null,
"admaza.in": null,
"impact-ad.jp": null,
"gandrad.org": null,
"porn-ad.org": null,
"trackonomics.net": null,
"google-rank.org": null,
"adnz.co": null,
"adro.co": null,
"adzmaza.in": null,
"opentracker.net": null,
"ppctracking.net": null,
"smartracker.net": null,
"trackedlink.net": null,
"roitracking.net": null,
"layer-ad.org": null,
"oas.luxweb.com": null,
"adsmws.cloudapp.net": null,
"e-webtrack.net": null,
"maxtracker.net": null,
"trackedweb.net": null,
"trackmyweb.net": null,
"contextads.net": null,
"silverads.net": null,
"camleyads.info": null,
"adigniter.org": null,
"sevenads.net": null,
"visit.homepagle.com": null,
"adzincome.in": null,
"fnro4yu0.loan": null,
"holexknw.loan": null,
"mstracker.net": null,
"track-web.net": null,
"wisetrack.net": null,
"ad20.net": null,
"adv9.net": null,
"usenetnl.download": null,
"adchannels.in": null,
"respond-adserver.cloudapp.net": null,
"trackcmp.net": null,
"tracktrk.net": null,
"zmctrack.net": null,
"oas.skyscanner.net": null,
"advnet.xyz": null,
"experianmarketingservices.digital": null,
"img.servint.net": null,
"advise.co": null,
"abnad.net": null,
"adf01.net": null,
"adprs.net": null,
"adrsp.net": null,
"bf-ad.net": null,
"dynad.net": null,
"analytics.epi.es": null,
"rentracks.jp": null,
"estrack.net": null,
"bbtrack.net": null,
"ad-srv.net": null,
"adbard.net": null,
"addoor.net": null,
"adgine.net": null,
"adhigh.net": null,
"adkick.net": null,
"adpays.net": null,
"adrife.net": null,
"adviva.net": null,
"advsnx.net": null,
"geniad.net": null,
"optiad.net": null,
"polyad.net": null,
"adlook.net": null,
"adrent.net": null,
"desiad.net": null,
"adcarem.co": null,
"find-ip-address.org": null,
"googleads.g.doubleclick.net": null,
"ad-back.net": null,
"adgoi-1.net": null,
"adowner.net": null,
"bidhead.net": null,
"tra.pmdstatic.net": null,
"cdn.trafficexchangelist.com": null,
"analytics.iraiser.eu": null,
"adc-serv.net": null,
"adbasket.net": null,
"addynamo.net": null,
"admagnet.net": null,
"intextad.net": null,
"onlyalad.net": null,
"adadvisor.net": null,
"adglamour.net": null,
"adtegrity.net": null,
"advertpay.net": null,
"augmentad.net": null,
"elasticad.net": null,
"networkad.net": null,
"beacon.squixa.net": null,
"blogads.com": null,
"individuad.net": null,
"addcontrol.net": null,
"adcastplus.net": null,
"adtransfer.net": null,
"adverticum.net": null,
"content-ad.net": null,
"widgetlead.net": null,
"adtr.io": null,
"wstats.e-wok.tv": null,
"ad-balancer.net": null,
"ad-delivery.net": null,
"dashboardad.net": null,
"adimpression.net": null,
"scriptall.ga": null,
"arcadebannerexchange.org": null,
"beacon.gutefrage.net": null,
"gripdownload.co": null,
"stat.ws.126.net": null,
"admarketplace.net": null,
"tracker2.apollo-mail.net": null,
"advertisingpath.net": null,
"adultcommercial.net": null,
"spotx.tv": null,
"adultadvertising.net": null,
"adless.io": null,
"adapex.io": null,
"adlive.io": null,
"adnami.io": null,
"abbeyblog.me": null,
"ad.duga.jp": null,
"drowadri.racing": null,
"adverti.io": null,
"knowlead.io": null,
"adku.co": null,
"popads.media": null,
"analytics.codigo.se": null,
"pixtrack.in": null,
"w5statistics.info": null,
"w9statistics.info": null,
"abtracker.us": null,
"w4statistics.info": null,
"sethads.info": null,
"trackword.biz": null,
"advmaker.ru": null,
"click.aristotle.net": null,
"adalliance.io": null,
"adexchange.io": null,
"count.yandeg.ru": null,
"tracking.vid4u.org": null,
"traffic.brand-wall.net": null,
"advatar.to": null,
"spylog.ru": null,
"superstat.info": null,
"westatess.info": null,
"manager.koocash.fr": null,
"hostingcloud.party": null,
"brand.net": null,
"adip.ly": null,
"admeira.ch": null,
"widgetbanner.mobi": null,
"wwwstats.info": null,
"my-stats.info": null,
"analytics.rechtslupe.org": null,
"analytics.truecarbon.org": null,
"adorika.net": null,
"ad.idgtn.net": null,
"ad.jamba.net": null,
"media.studybreakmedia.com": null,
"buysellads.net": null,
"hostingcloud.download": null,
"affiligay.net": null,
"cloudflare.solutions": null,
"gameads.com": null,
"analyticapi.piri.net": null,
"ad.pickple.net": null,
"tracking.thehut.net": null,
"adtotal.pl": null,
"tracking.ehavior.net": null,
"tracking.listhub.net": null,
"onlinereserchstatistics.online": null,
"affiliates.bookdepository.com": null,
"startstat.ru": null,
"tracking.wlscripts.net": null,
"analytics.reyrey.net": null,
"webstat.no": null,
"analytics.carambo.la": null,
"jumplead.io": null,
"objects.tremormedia.com": null,
"analytics.edgekey.net": null,
"analytics.traidnt.net": null,
"analytics.dvidshub.net": null,
"event.dkb.de": null,
"beead.net": null,
"tags.cdn.circlesix.co": null,
"analytics.witglobal.net": null,
"advertica.ae": null,
"statpipe.ru": null,
"track2.mycliplister.com": null,
"affiliate.cx": null,
"deals.buxr.net": null,
"tms-st.cdn.ngenix.net": null,
"analytics.urx.io": null,
"analytics.mailmunch.co": null,
"adplusplus.fr": null,
"googleadapis.l.google.com": null,
"blogverzeichnis.eu": null,
"analytics.industriemagazin.net": null,
"analytics.cmg.net": null,
"upads.info": null,
"landsraad.cc": null,
"fairad.co": null,
"tracking.oe24.at": null,
"tracking.customerly.io": null,
"analytics.arz.at": null,
"tracking.krone.at": null,
"crazyad.net": null,
"ad.kissanime.io": null,
"tracking.kurier.at": null,
"analytics.tio.ch": null,
"visits.lt": null,
"analytics.suggestv.io": null,
"adbooth.net": null,
"beacon.nuskin.com": null,
"affiliates.easydate.biz": null,
"adgoi.com": null,
"stabilityappointdaily.xyz": null,
"beacon.tingyun.com": null,
"privilegebedroomlate.xyz": null,
"honestlypopularvary.xyz": null,
"timeslogtn.timesnow.tv": null,
"ad.kisscartoon.io": null,
"inspiringsweater.xyz": null,
"beacon.viewlift.com": null,
"analytics.solidbau.at": null,
"cruftexcision.xyz": null,
"mataharirama.xyz": null,
"mobsoftffree.xyz": null,
"beacon.riskified.com": null,
"tripedrated.xyz": null,
"alltheladyz.xyz": null,
"tchhelpdmn.xyz": null,
"zapstorage.xyz": null,
"track.qcri.org": null,
"aleinvest.xyz": null,
"quicktask.xyz": null,
"flac2flac.xyz": null,
"alemoney.xyz": null,
"proj2018.xyz": null,
"tidafors.xyz": null,
"checkapi.xyz": null,
"mp3toavi.xyz": null,
"permenor.xyz": null,
"zylstina.xyz": null,
"ficusoid.xyz": null,
"kxqvnfcg.xyz": null,
"js.stroeermediabrands.de": null,
"janrain.xyz": null,
"elwraek.xyz": null,
"fyredet.xyz": null,
"patoris.xyz": null,
"albireo.xyz": null,
"affiliate.productreview.com.au": null,
"cndhit.xyz": null,
"verata.xyz": null,
"acamar.xyz": null,
"alamak.xyz": null,
"pcruxm.xyz": null,
"hivps.xyz": null,
"avero.xyz": null,
"bh8yx.xyz": null,
"retag.xyz": null,
"bnbir.xyz": null,
"img.hostmonster.com": null,
"1e0y.xyz": null,
"hdat.xyz": null,
"hhit.xyz": null,
"beacon.errorception.com": null,
"beacon.heliumnetwork.com": null,
"beacon.securestudies.com": null,
"beacon.wikia-services.com": null,
"1q2w3.website": null,
"track.kandle.org": null,
"adgebra.in": null,
"analyzer.qmerce.com": null,
"humanclick.com": null,
"analytics.paddle.com": null,
"event.previewnetworks.com": null,
"livestats.la7.tv": null,
"tracker.mtrax.net": null,
"gitcdn.site": null,
"track.atom-data.io": null,
"onhercam.com": null,
"webpushcloud.info": null,
"content.liveuniverse.com": null,
"statistics.infowap.info": null,
"ad.cooks.com": null,
"ad.evozi.com": null,
"affiliategateways.co": null,
"adexchangecloud.com": null,
"adku.com": null,
"jumplead.com": null,
"stat.api.2gis.ru": null,
"videoplayer2.xyz": null,
"analysis.focalprice.com": null,
"alltagcloud.info": null,
"mytestminer.xyz": null,
"track2.me": null,
"iv.doubleclick.net": null,
"ad.fnnews.com": null,
"tracking.novem.pl": null,
"jstracker.com": null,
"webtracker.apicasystem.com": null,
"yllasatra.xyz": null,
"ad.icasthq.com": null,
"ad.vidaroo.com": null,
"ad.jamster.com": null,
"adorika.com": null,
"metrics.aviasales.ru": null,
"beacon.aimtell.com": null,
"valkrana.xyz": null,
"webtracker.educationconnection.com": null,
"clarium.global.ssl.fastly.net": null,
"tracker.streamroot.io": null,
"elmenor.xyz": null,
"track2.dulingo.com": null,
"hostingcloud.stream": null,
"track.g-bot.net": null,
"adbit.co": null,
"ijuawecwqhwyou.bid": null,
"beiren.xyz": null,
"daecan.xyz": null,
"ilinan.xyz": null,
"ad.outsidehub.com": null,
"ad.reklamport.com": null,
"ad.lyricswire.com": null,
"tracker.publico.pt": null,
"clickwith.bid": null,
"ltcvpgyouvxya.bid": null,
"pulse-analytics-beacon.reutersmedia.net": null,
"adgebra.co.in": null,
"ad.foxnetworks.com": null,
"w.homes.yahoo.net": null,
"tracking.goodgamestudios.com": null,
"adsummos.net": null,
"analytics.matchbin.com": null,
"ad.directmirror.com": null,
"clickx.io": null,
"analytics.websolute.it": null,
"analytics.digitouch.it": null,
"ad.mesomorphosis.com": null,
"ad.theepochtimes.com": null,
"tracking.trovaprezzi.it": null,
"comscore.com": null,
"odyoudvaar.bid": null,
"track.redirecting2.net": null,
"bannerperformance.net": null,
"tracking.conversionlab.it": null,
"tracking.conversion-lab.it": null,
"analytics.rtbf.be": null,
"clientlog.portal.office.com": null,
"track.cordial.io": null,
"track.codepen.io": null,
"ad.iloveinterracial.com": null,
"dup.baidustatic.com": null,
"stats.teledyski.info": null,
"track.mobicast.io": null,
"asterpix.com": null,
"epnt.ebay.com": null,
"lapi.ebay.com": null,
"ilapi.ebay.com": null,
"analytics.rambla.be": null,
"bannerbridge.net": null,
"adnext.fr": null,
"eps-analyzer.de": null,
"hyperbanner.net": null,
"analytics.belgacom.be": null,
"neads.delivery": null,
"ttdetect.staticimgfarm.com": null,
"stat.bilibili.tv": null,
"clkdown.info": null,
"smartology.co": null,
"alogationa.co": null,
"ourbanners.net": null,
"windowne.info": null,
"qom006.site": null,
"video1404.info": null,
"analytics-static.ugc.bazaarvoice.com": null,
"expresided.info": null,
"solutionzip.info": null,
"eanalyzer.de": null,
"4dsbanner.net": null,
"downlossinen.info": null,
"aeros01.tk": null,
"aeros02.tk": null,
"aeros03.tk": null,
"aeros04.tk": null,
"aeros05.tk": null,
"aeros06.tk": null,
"aeros07.tk": null,
"aeros08.tk": null,
"aeros09.tk": null,
"aeros10.tk": null,
"aeros11.tk": null,
"aeros12.tk": null,
"contentdigital.info": null,
"impressioncontent.info": null,
"seecontentdelivery.info": null,
"webcontentdelivery.info": null,
"zumcontentdelivery.info": null,
"analytics.30m.com": null,
"analytics.r17.com": null,
"inewcontentdelivery.info": null,
"requiredcollectfilm.info": null,
"track.derbund.ch": null,
"analytics.21cn.com": null,
"analytics.favcy.com": null,
"analytics.revee.com": null,
"analytics.brave.com": null,
"track.24heures.ch": null,
"analytics.conmio.com": null,
"analytics.kapost.com": null,
"analytics.piksel.com": null,
"analytics.prezly.com": null,
"analytics.aasaam.com": null,
"analytics.jabong.com": null,
"analytics.posttv.com": null,
"analytics.thetab.com": null,
"analytics.zg-api.com": null,
"analytics.artirix.com": null,
"analytics.cincopa.com": null,
"analytics.pinpoll.com": null,
"analytics.thenest.com": null,
"analytics.infobae.com": null,
"adlure.net": null,
"analytics.audioeye.com": null,
"analytics.hpprintx.com": null,
"analytics.orenshmu.com": null,
"analytics.freespee.com": null,
"analytics.mindjolt.com": null,
"analytics.upworthy.com": null,
"microad.jp": null,
"analytics.vendemore.com": null,
"analytics.grupogodo.com": null,
"analytics.sportybet.com": null,
"analytics.teespring.com": null,
"analytics.volvocars.com": null,
"cnstats.cdev.eu": null,
"letsgoshopping.tk": null,
"tracksys.developlabs.net": null,
"analytics.closealert.com": null,
"analytics.groupe-seb.com": null,
"analytics.snidigital.com": null,
"analytics.linkwelove.com": null,
"analytics.traderlink.com": null,
"analytics.themarketiq.com": null,
"analytics.schoolwires.com": null,
"analytics.socialblade.com": null,
"analytics.whatculture.com": null,
"analytics.atomiconline.com": null,
"analytics.cohesionapps.com": null,
"visistat.com": null,
"analytics.midwesternmac.com": null,
"analytics.vanillaforums.com": null,
"analytics.ziftsolutions.com": null,
"analytics.apnewsregistry.com": null,
"analytics.hindustantimes.com": null,
"analytics.convertlanguage.com": null,
"sftrack.searchforce.net": null,
"track.bluecompany.cl": null,
"pixel.wp.com": null,
"track.bernerzeitung.ch": null,
"werbe-sponsor.de": null,
"analytics.onlyonlinemarketing.com": null,
"analytics.strangeloopnetworks.com": null,
"analytics.disneyinternational.com": null,
"webads.co.nz": null,
"cookies.reedbusiness.nl": null,
"track.parse.ly": null,
"track.sauce.ly": null,
"doubleclick.com": null,
"adzoe.de": null,
"count.rin.ru": null,
"htl.bid": null,
"adrise.de": null,
"pixiedust.buzzfeed.com": null,
"adserve.com": null,
"tracking.s24.com": null,
"adheart.de": null,
"adtraxx.de": null,
"adprovi.de": null,
"paid4ad.de": null,
"cashtrafic.info": null,
"tracking.hi-pi.com": null,
"tracking.koego.com": null,
"tracking.lengow.com": null,
"tracking.cat898.com": null,
"tracking.olx-st.com": null,
"webtracker.jp": null,
"tracking.g2crowd.com": null,
"tracking.i-vengo.com": null,
"tracking.batanga.com": null,
"tracking.realtor.com": null,
"adrank24.de": null,
"tracking.pacharge.com": null,
"tracking.rapidape.com": null,
"tracking.ancestry.com": null,
"tracking.battleon.com": null,
"tracking.nextdoor.com": null,
"tracking.times247.com": null,
"stats.mos.ru": null,
"tracking.tradeking.com": null,
"tracking.carprices.com": null,
"tracking.eurosport.com": null,
"tracking.mycapture.com": null,
"tracking.tidalhifi.com": null,
"cdna.tremormedia.com": null,
"tracking.musixmatch.com": null,
"tracking.target2sell.com": null,
"tracking.porndoelabs.com": null,
"traffic.tc-clicks.com": null,
"arcadebannerexchange.net": null,
"webtrack.biz": null,
"adpionier.de": null,
"tracking.unrealengine.com": null,
"metric.inetcore.com": null,
"tracking.searchmarketing.com": null,
"tracking.resumecompanion.com": null,
"tracking.softwareprojects.com": null,
"pro-advert.de": null,
"stats.staging.suite101.com": null,
"liwimgti.bid": null,
"k9anf8bc.webcam": null,
"exponderle.pro": null,
"g-content.bid": null,
"eimgxlsqj.bid": null,
"filenlgic.bid": null,
"fjmxpixte.bid": null,
"event-listener.air.tv": null,
"syndication1.viraladnetwork.net": null,
"adtelligence.de": null,
"silverpop.com": null,
"bcoavtimgn.bid": null,
"feacamnliz.bid": null,
"ghizipjlsi.bid": null,
"adultsense.com": null,
"minexmr.stream": null,
"axbpixbcucv.bid": null,
"unblocksite.info": null,
"stat.ruvr.ru": null,
"tracker.euroweb.net": null,
"arqxpopcywrr.bid": null,
"bjkookfanmxx.bid": null,
"nrwofsfancse.bid": null,
"widget.wombo.gg": null,
"pmzktktfanzem.bid": null,
"yxwdppixvzxau.bid": null,
"connect.facebook.com": null,
"redirector.googlevideo.com": null,
"suggestqueries.google.com": null,
"connect.facebook.net": null,
"platform.twitter.com": null,
"api.areametrics.com": null,
"api.beaconsinspace.com": null,
"mobileapi.mobiquitynetworks.com": null,
"incoming-data-sense360.s3.amazonaws.com": null,
"ios-quinoa-events-prod.sense360eng.com": null,
"ios-quinoa-high-frequency-events-prod.sense360eng.com": null,
"v1.blueberry.cloud.databerries.com": null,
"outbrain.com": null,
"taboola.com": null };
var bad_da_host_exact_flag = 1239 > 0 ? true : false;  // test for non-zero number of rules
    
// 3 rules as an efficient NFA RegExp:
var bad_da_host_RegExp = /^(?:[\w-]+\.)*?(?:images\.(?=([\s\S]*?\.criteo\.net))\1|analytics\-beacon\-(?=([\s\S]*?\.amazonaws\.com))\2|trk(?=([\s\S]*?\.vidible\.tv))\3)/i;
var bad_da_host_regex_flag = 3 > 0 ? true : false;  // test for non-zero number of rules

// 295 rules:
var bad_da_hostpath_JSON = { "depositfiles.com/stats.php": null,
"ad.atdmt.com/i/a.html": null,
"ad.atdmt.com/i/a.js": null,
"imagesnake.com/includes/js/pops.js": null,
"googletagmanager.com/gtm.js": null,
"hulkshare.com/stats.php": null,
"domaintools.com/tracker.php": null,
"google-analytics.com/analytics.js": null,
"linkconnector.com/traffic_record.php": null,
"elb.amazonaws.com/partner.gif": null,
"baidu.com/js/log.js": null,
"cloudfront.net/analytics.js": null,
"windows.net/script/p.js": null,
"autoline-top.com/counter.php": null,
"cloudfront.net/log.js": null,
"baidu.com/h.js": null,
"pluso.ru/counter.php": null,
"viglink.com/images/pixel.gif": null,
"nyafilmer.com/wp-content/themes/keremiya1/js/script.js": null,
"disqus.com/stats.html": null,
"twitvid.com/api/tracking.php": null,
"amazonaws.com/g.aspx": null,
"facebook.com/common/scribe_endpoint.php": null,
"freebunker.com/includes/js/cat.js": null,
"sltrib.com/csp/mediapool/sites/Shared/assets/csp/includes/omniture/SiteCatalystCode_H_17.js": null,
"plista.com/iframeShowItem.php": null,
"movad.de/c.ount": null,
"allmyvideos.net/player/ova-jw.swf": null,
"cloudfront.net/js/reach.js": null,
"myway.com/gca_iframe.html": null,
"codecguide.com/stats.js": null,
"cloudfront.net/scripts/js3caf.js": null,
"wheninmanila.com/wp-content/uploads/2012/12/Marie-France-Buy-1-Take-1-Deal-Discount-WhenInManila.jpg": null,
"eastmoney.com/counter.js": null,
"eageweb.com/stats.php": null,
"elb.amazonaws.com/small.gif": null,
"thefile.me/apu.php": null,
"dpstatic.com/banner.png": null,
"wired.com/tracker.js": null,
"turboimagehost.com/p1.js": null,
"barclaycard.co.uk/cs/static/js/esurveys/esurveys.js": null,
"skyrock.net/js/stats_blog.js": null,
"cgmlab.com/tools/geotarget/custombanner.js": null,
"googletagservices.com/dcm/dcmads.js": null,
"video44.net/gogo/yume-h.swf": null,
"piano-media.com/bucket/novosense.swf": null,
"brightcove.com/1pix.gif": null,
"hitleap.com/assets/banner.png": null,
"mercola.com/Assets/js/omniture/sitecatalyst/mercola_s_code.js": null,
"cafenews.pl/mpl/static/static.js": null,
"washingtonpost.com/rw/sites/twpweb/js/init/init.track-header-1.0.0.js": null,
"websitehome.co.uk/seoheap/cheap-web-hosting.gif": null,
"cloudfront.net/scripts/cookies.js": null,
"tubepornclassic.com/js/111.js": null,
"streams.tv/js/bn5.js": null,
"ulogin.ru/js/stats.js": null,
"ge.com/sites/all/themes/ge_2012/assets/js/bin/s_code.js": null,
"revisionworld.co.uk/sites/default/files/imce/Double-MPU2-v2.gif": null,
"vodo.net/static/images/promotion/utorrent_plus_buy.png": null,
"s-msn.com/s/js/loader/activity/trackloader.min.js": null,
"blogsdna.com/wp-content/themes/blogsdna2011/images/advertisments.png": null,
"charter.com/static/scripts/mock/tracking.js": null,
"9msn.com.au/share/com/js/fb_google_intercept.js": null,
"csmonitor.com/extension/csm_base/design/standard/javascript/adobe/s_code.js": null,
"adimgs.t2b.click/assets/js/ttbir.js": null,
"zylom.com/pixel.jsp": null,
"yourtv.com.au/share/com/js/fb_google_intercept.js": null,
"playstation.com/pscomauth/groups/public/documents/webasset/community_secured_s_code.js": null,
"gannett-cdn.com/appservices/partner/sourcepoint/sp-mms-client.js": null,
"snazzyspace.com/generators/viewer-counter/counter.php": null,
"webhostranking.com/images/bluehost-coupon-banner-1.gif": null,
"wheninmanila.com/wp-content/uploads/2014/02/DTC-Hardcore-Quadcore-300x100.gif": null,
"wheninmanila.com/wp-content/uploads/2011/05/Benchmark-Email-Free-Signup.gif": null,
"nzbking.com/static/nzbdrive_banner.swf": null,
"adap.tv/redir/client/static/as3adplayer.swf": null,
"thumblogger.com/thumblog/top_banner_silver.js": null,
"pimpandhost.com/static/html/iframe.html": null,
"skyrock.net/img/pix.gif": null,
"csmonitor.com/extension/csm_base/design/csm_design/javascript/omniture/s_code.js": null,
"watchuseek.com/site/forabar/zixenflashwatch.swf": null,
"forms.aweber.com/form/styled_popovers_and_lightboxes.js": null,
"fncstatic.com/static/all/js/geo.js": null,
"aircanada.com/shared/common/sitecatalyst/s_code.js": null,
"military.com/data/popup/new_education_popunder.htm": null,
"phonearena.com/_track.php": null,
"hotdeals360.com/static/js/kpwidgetweb.js": null,
"nitrobahn.com.s3.amazonaws.com/theme/getclickybadge.gif": null,
"sexvideogif.com/msn.js": null,
"aeroplan.com/static/js/omniture/s_code_prod.js": null,
"wheninmanila.com/wp-content/uploads/2014/04/zion-wifi-social-hotspot-system.png": null,
"cloudfront.net/track.html": null,
"jeuxvideo.com/contenu/medias/video/countv.php": null,
"ibtimes.com/player/stats.swf": null,
"liveonlinetv247.com/images/muvixx-150x50-watch-now-in-hd-play-btn.gif": null,
"baymirror.com/static/img/bar.gif": null,
"amazonaws.com/pmb-musics/download_itunes.png": null,
"audiusa.com/us/brand/en.usertracking_javascript.js": null,
"naptol.com/usr/local/csp/staticContent/js/ga.js": null,
"attorrents.com/static/images/download3.png": null,
"ultimatewindowssecurity.com/securitylog/encyclopedia/images/allpartners.swf": null,
"expressen.se/static/scripts/s_code.js": null,
"nih.gov/share/scripts/survey.js": null,
"emergencymedicalparamedic.com/wp-content/uploads/2011/12/anatomy.gif": null,
"btkitty.org/static/images/880X60.gif": null,
"dexerto.com/app/uploads/2016/11/Gfuel-LemoNade.jpg": null,
"cdnplanet.com/static/rum/rum.js": null,
"libertyblitzkrieg.com/wp-content/uploads/2012/09/cc200x300.gif": null,
"saabsunited.com/wp-content/uploads/REALCAR-SAABSUNITED-5SEC.gif": null,
"shopify.com/track.js": null,
"better-explorer.com/wp-content/uploads/2013/07/hf.5.png": null,
"paypal.com/acquisition-app/static/js/s_code.js": null,
"dl-protect.com/pop.js": null,
"ibrod.tv/ib.php": null,
"ultimatewindowssecurity.com/images/banner80x490_WSUS_FreeTool.jpg": null,
"addtoany.com/menu/transparent.gif": null,
"btkitty.com/static/images/880X60.gif": null,
"soe.com/js/web-platform/web-data-tracker.js": null,
"tpb.piraten.lu/static/img/bar.gif": null,
"privacytool.org/AnonymityChecker/js/fontdetect.js": null,
"microsoft.com/getsilverlight/scripts/silverlight/SilverlightAtlas-MSCOM-Tracking.js": null,
"vidyoda.com/fambaa/chnls/ADSgmts.ashx": null,
"themag.co.uk/assets/BV200x90TOPBANNER.png": null,
"ebizmbainc.netdna-cdn.com/images/tab_sponsors.gif": null,
"johnbridge.com/vbulletin/images/tyw/cdlogo-john-bridge.jpg": null,
"watchuseek.com/media/longines_legenddiver.gif": null,
"kuiken.co/static/w.js": null,
"downloadsmais.com/imagens/download-direto.gif": null,
"watchseries.eu/images/download.png": null,
"staticbucket.com/boost//Scripts/libs/flickity.js": null,
"lightboxcdn.com/static/identity.html": null,
"crabcut.net/popup.js": null,
"whatreallyhappened.com/webpageimages/banners/uwslogosm.jpg": null,
"taringa.net/ajax/track-visit.php": null,
"static.pes-serbia.com/prijatelji/zero.png": null,
"better-explorer.com/wp-content/uploads/2012/09/credits.png": null,
"lexus.com/lexus-share/js/campaign_tracking.js": null,
"livetradingnews.com/wp-content/uploads/vamp_cigarettes.png": null,
"razor.tv/site/servlet/tracker.jsp": null,
"shopping.com/sc/pac/sdc_widget_v2.0_proxy.js": null,
"pimpandhost.com/images/pah-download.gif": null,
"samsung.com/ph/nextisnow/files/javascript.js": null,
"careerwebsite.com/distrib_pages/jobs.cfm": null,
"pcgamesn.com/sites/default/files/SE4L.JPG": null,
"static.tumblr.com/dhqhfum/WgAn39721/cfh_header_banner_v2.jpg": null,
"investegate.co.uk/Weblogs/IGLog.aspx": null,
"quintcareers.4jobs.com/Common/JavaScript/functions.tracking.js": null,
"images.military.com/pixel.gif": null,
"ino.com/img/sites/mkt/click.gif": null,
"whitedolly.com/wcf/images/redbar/logo_neu.gif": null,
"desiretoinspire.net/storage/layout/royalcountessad.gif": null,
"webmd.com/dtmcms/live/webmd/PageBuilder_Assets/JS/oas35.js": null,
"xbox-scene.com/crave/logo_on_white_s160.jpg": null,
"technewsdaily.com/crime-stats/local_crime_stats.php": null,
"videobull.to/wp-content/themes/videozoom/images/stream-hd-button.gif": null,
"fileplanet.com/fileblog/sub-no-ad.shtml": null,
"androidfilehost.com/libs/otf/stats.otf.php": null,
"uploadshub.com/downloadfiles/download-button-blue.gif": null,
"flashi.tv/histats.php": null,
"sexier.com/services/adsredirect.ashx": null,
"meanjin.com.au/static/images/sponsors.jpg": null,
"statig.com.br/pub/setCookie.js": null,
"saabsunited.com/wp-content/uploads/rbm21.jpg": null,
"saabsunited.com/wp-content/uploads/USACANADA.jpg": null,
"jillianmichaels.com/images/publicsite/advertisingslug.gif": null,
"sexilation.com/wp-content/uploads/2013/01/Untitled-1.jpg": null,
"cardstore.com/affiliate.jsp": null,
"healthcarejobsite.com/Common/JavaScript/functions.tracking.js": null,
"pcgamesn.com/sites/default/files/Se4S.jpg": null,
"washingtonpost.com/wp-srv/javascript/piggy-back-on-ads.js": null,
"watchuseek.com/media/clerc-final.jpg": null,
"ewrc-results.com/images/horni_ewrc_result_banner3.jpg": null,
"myanimelist.net/static/logging.html": null,
"rednationonline.ca/Portals/0/derbystar_leaderboard.jpg": null,
"worldnow.com/global/tools/video/Namespace_VideoReporting_DW.js": null,
"youwatch.org/vod-str.html": null,
"domainapps.com/assets/img/domain-apps.gif": null,
"cruisesalefinder.co.nz/affiliates.html": null,
"kitguru.net/wp-content/wrap.jpg": null,
"messianictimes.com/images/Jews%20for%20Jesus%20Banner.png": null,
"friday-ad.co.uk/endeca/afccontainer.aspx": null,
"mnginteractive.com/live/js/omniture/SiteCatalystCode_H_22_1_NC.js": null,
"jappy.tv/i/wrbng/abb.png": null,
"washtimes.com/static/images/SelectAutoWeather_v2.gif": null,
"webtutoriaux.com/services/compteur-visiteurs/index.php": null,
"greyorgray.com/images/Fast%20Business%20Loans%20Ad.jpg": null,
"timesnow.tv/googlehome.cms": null,
"hostingtoolbox.com/bin/Count.cgi": null,
"imageteam.org/upload/big/2014/06/22/53a7181b378cb.png": null,
"shareit.com/affiliate.html": null,
"syndication.visualthesaurus.com/std/vtad.js": null,
"picturevip.com/imagehost/top_banners.html": null,
"videobull.to/wp-content/themes/videozoom/images/gotowatchnow.png": null,
"kau.li/yad.js": null,
"zipcode.org/site_images/flash/zip_v.swf": null,
"prospects.ac.uk/assets/js/prospectsWebTrends.js": null,
"videoszoofiliahd.com/wp-content/themes/vz/js/p.js": null,
"file.org/fo/scripts/download_helpopt.js": null,
"watchuseek.com/media/wus-image.jpg": null,
"klm.com/travel/generic/static/js/measure_async.js": null,
"qbn.com/media/static/js/ga.js": null,
"wearetennis.com/img/common/bnp-logo.png": null,
"arstechnica.com/dragons/breath.gif": null,
"desiretoinspire.net/storage/layout/modmaxbanner.gif": null,
"johnbridge.com/vbulletin/images/tyw/wedi-shower-systems-solutions.png": null,
"letour.fr/img/v6/sprite_partners_2x.png": null,
"downloadian.com/assets/banner.jpg": null,
"staticice.com.au/cgi-bin/stats.cgi": null,
"cash9.org/assets/img/banner2.gif": null,
"script.idgentertainment.de/gt.js": null,
"watchseries.eu/js/csspopup.js": null,
"js.static.m1905.cn/pingd.js": null,
"mywot.net/files/wotcert/vipre.png": null,
"homepage-baukasten.de/cookie.php": null,
"gold-prices.biz/gold_trading_leader.gif": null,
"makeagif.com/parts/fiframe.php": null,
"sofascore.com/geoip.js": null,
"as.jivox.com/jivox/serverapis/getcampaignbysite.php": null,
"youwatch.org/driba.html": null,
"youwatch.org/9elawi.html": null,
"youwatch.org/iframe1.html": null,
"binsearch.info/iframe.php": null,
"nih.gov/medlineplus/images/mplus_en_survey.js": null,
"publicdomaintorrents.info/srsbanner.gif": null,
"interracialbangblog.info/banner.jpg": null,
"gus.host/coins.js": null,
"filestream.me/requirements/images/ed.gif": null,
"youtube-nocookie.com/robots.txt": null,
"scriptlance.com/cgi-bin/freelancers/ref_click.cgi": null,
"celebstoner.com/assets/images/img/top/420VapeJuice960x90V3.gif": null,
"forward.com/workspace/assets/newimages/amazon.png": null,
"euronews.com/media/farnborough/farnborough_wp.jpg": null,
"nbcudigitaladops.com/hosted/housepix.gif": null,
"russellgrant.com/hostedsearch/panelcounter.aspx": null,
"scientopia.org/public_html/clr_lympholyte_banner.gif": null,
"serial.sw.cracks.me.uk/img/logo.gif": null,
"unblockedpiratebay.com/static/img/bar.gif": null,
"vipi.tv/ad.php": null,
"releaselog.net/uploads2/656d7eca2b5dd8f0fbd4196e4d0a2b40.jpg": null,
"dj.rasset.ie/dotie/js/rte.ads.js": null,
"momtastic.com/libraries/pebblebed/js/pb.track.js": null,
"d-h.st/assets/img/download1.png": null,
"go4up.com/assets/img/download-button.png": null,
"checker.openwebtorrent.com/digital-ocean.jpg": null,
"better-explorer.com/wp-content/uploads/2013/10/PoweredByNDepend.png": null,
"atom-data.io/session/latest/track.html": null,
"watchop.com/player/watchonepiece-gao-gamebox.swf": null,
"fantasti.cc/ajax/gw.php": null,
"letswatchsomething.com/images/filestreet_banner.jpg": null,
"kleisauke.nl/static/img/bar.gif": null,
"24hourfitness.com/includes/script/siteTracking.js": null,
"englishgrammar.org/images/30off-coupon.png": null,
"swatchseries.to/bootstrap.min.js": null,
"mail.yahoo.com/mc/md.php": null,
"cams.com/p/cams/cpcs/streaminfo.cgi": null,
"judgeporn.com/video_pop.php": null,
"infogr.am/js/metrics.js": null,
"filestream.me/requirements/images/cialis_generic.gif": null,
"merchantcircle.com/static/track.js": null,
"playomat.de/sfye_noscript.php": null,
"odnaknopka.ru/stat.js": null,
"lazygirls.info/click.php": null,
"cloudfront.net/rc.js": null,
"hwbot.org/banner.img": null,
"bc.vc/images/megaload.gif": null,
"uramov.info/wav/wavideo.html": null,
"jivox.com/jivox/serverapis/getcampaignbyid.php": null,
"rtlradio.lu/stats.php": null,
"3dsemulator.org/img/download.png": null,
"ablacrack.com/popup-pvd.js": null,
"twinsporn.net/images/free-penis-pills.png": null,
"mapandroute.de/log.xhr": null,
"playgirl.com/pg/media/prolong_ad.png": null,
"digitizor.com/wp-content/digimages/xsoftspyse.png": null,
"speedvid.net/ad.htm": null,
"cloudfront.net/dfpd.js": null,
"vwdealerdigital.com/cdn/sd.js": null,
"trutv.com/includes/mods/iframes/mgid-blog.php": null,
"devilgirls.co/images/devil.gif": null,
"piano-media.com/auth/index.php": null,
"jayisgames.com/maxcdn_160x250.png": null,
"viralogy.com/javascript/viralogy_tracker.js": null,
"free-tv-video-online.me/resources/js/counter.js": null,
"v.blog.sohu.com/dostat.do": null,
"publicdomaintorrents.info/grabs/hdsale.png": null,
"imgdino.com/gsmpop.js": null,
"cclickvidservgs.com/mattel/cclick.js": null,
"lijit.com/adif_px.php": null,
"virginholidays.co.uk/_assets/js/dc_storm/track.js": null,
"cdn.cdncomputer.com/js/main.js": null,
"ha.ckers.org/images/sectheory-bot.png": null,
"ha.ckers.org/images/fallingrock-bot.png": null,
"vbs.tv/tracker.html": null,
"thevideo.me/mba/cds.js": null,
"xxxselected.com/cdn_files/dist/js/blockPlaces.js": null,
"pv-tech.org/images/suntech_m2fbblew.png": null };
var bad_da_hostpath_exact_flag = 295 > 0 ? true : false;  // test for non-zero number of rules
    
// 972 rules as an efficient NFA RegExp:
var bad_da_hostpath_RegExp = /^(?:[\w-]+\.)*?(?:doubleclick\.net\/adx\/|piano\-media\.com\/uid\/|doubleclick\.net\/adj\/|jobthread\.com\/t\/|pornfanplace\.com\/js\/pops\.|porntube\.com\/adb\/|quantserve\.com\/pixel\/|doubleclick\.net\/pixel|baidu\.com\/pixel|addthiscdn\.com\/live\/|doubleclick\.net\/ad\/|adf\.ly\/_|netdna\-ssl\.com\/tracker\/|imageshack\.us\/ads\/|firedrive\.com\/tools\/|freakshare\.com\/banner\/|adform\.net\/banners\/|baidu\.com\/ecom|amazonaws\.com\/analytics\.|adultfriendfinder\.com\/banners\/|facebook\.com\/tr|widgetserver\.com\/metrics\/|veeseo\.com\/tracking\/|google\-analytics\.com\/plugins\/|channel4\.com\/ad\/|chaturbate\.com\/affiliates\/|sextronix\.com\/images\/|domaintools\.com\/partners\/|redtube\.com\/stats\/|view\.atdmt\.com\/partner\/|barnebys\.com\/widgets\/|google\.com\/analytics\/|adultfriendfinder\.com\/javascript\/|yahoo\.com\/track\/|yahoo\.com\/beacon\/|4tube\.com\/iframe\/|visiblemeasures\.com\/log|cloudfront\.net\/track|cursecdn\.com\/banner\/|pop6\.com\/banners\/|pcwdld\.com\/wp\-content\/plugins\/wbounce\/|google\-analytics\.com\/gtm\/js|propelplus\.com\/track\/|wupload\.com\/referral\/|dditscdn\.com\/log\/|adultfriendfinder\.com\/go\/|mediaplex\.com\/ad\/js\/|imagetwist\.com\/banner\/|wtprn\.com\/sponsors\/|xvideos\-free\.com\/d\/|wired\.com\/event|github\.com\/_stats|slashgear\.com\/stats\/|photobucket\.com\/track\/|hothardware\.com\/stats\/|healthtrader\.com\/banner\-|siberiantimes\.com\/counter\/|sex\.com\/popunder\/|xxvideo\.us\/ad728x15|pornoid\.com\/contents\/content_sources\/|voyeurhit\.com\/contents\/content_sources\/|lovefilm\.com\/partners\/|baidu\.com\/billboard\/pushlog\/|broadbandgenie\.co\.uk\/widget|xxxhdd\.com\/contents\/content_sources\/|topbucks\.com\/popunder\/|powvideo\.net\/ban\/|video\-cdn\.abcnews\.com\/ad_|livedoor\.com\/counter\/|vodpod\.com\/stats\/|zawya\.com\/ads\/|cnn\.com\/ad\-|msn\.com\/tracker\/|soundcloud\.com\/event|pornalized\.com\/contents\/content_sources\/|primevideo\.com\/uedata\/|shareasale\.com\/image\/|soufun\.com\/stats\/|hstpnetwork\.com\/ads\/|fwmrm\.net\/ad\/|rapidgator\.net\/images\/pics\/|fapality\.com\/contents\/content_sources\/|sawlive\.tv\/ad|appspot\.com\/stats|filecrypt\.cc\/p\.|static\.criteo\.net\/js\/duplo[^\w.%-]|sourceforge\.net\/log\/|adroll\.com\/pixel\/|secureupload\.eu\/banners\/|ad\.admitad\.com\/banner\/|conduit\.com\/\/banners\/|videowood\.tv\/ads|googlesyndication\.com\/sodar\/|googlesyndication\.com\/safeframe\/|red\-tube\.com\/popunder\/|phncdn\.com\/iframe|sparklit\.com\/counter\/|hosting24\.com\/images\/banners\/|pan\.baidu\.com\/api\/analytics|gamestar\.de\/_misc\/tracking\/|daylogs\.com\/counter\/|chameleon\.ad\/banner\/|nytimes\.com\/ads\/|twitter\.com\/i\/jot|spacash\.com\/popup\/|videoplaza\.tv\/proxy\/tracker[^\w.%-]|vidzi\.tv\/mp4|youtube\.com\/pagead\/|girlfriendvideos\.com\/ad|liutilities\.com\/partners\/|addthis\.com\/live\/|keepvid\.com\/ads\/|ad\.atdmt\.com\/s\/|theporncore\.com\/contents\/content_sources\/|static\.criteo\.net\/images[^\w.%-]|anysex\.com\/assets\/|doubleclick\.net\/pfadx\/video\.marketwatch\.com\/|citygridmedia\.com\/ads\/|chaturbate\.com\/creative\/|worldfree4u\.top\/banners\/|aliexpress\.com\/js\/beacon_|ad\.doubleclick\.net\/ddm\/trackclk\/|ad\.atdmt\.com\/i\/img\/|shareaholic\.com\/analytics_|dailymotion\.com\/track\-|dailymotion\.com\/track\/|kqzyfj\.com\/image\-|jdoqocy\.com\/image\-|tkqlhce\.com\/image\-|quora\.com\/_\/ad\/|twitter\.com\/metrics|ad\.atdmt\.com\/e\/|tube18\.sex\/tube18\.|cfake\.com\/images\/a\/|doubleclick\.net\/activity|hqq\.tv\/js\/betterj\/|ad\.admitad\.com\/fbanner\/|advfn\.com\/tf_|virool\.com\/widgets\/|reevoo\.com\/track\/|trrsf\.com\/metrics\/|pornmaturetube\.com\/content\/|mochiads\.com\/srv\/|howtogermany\.com\/banner\/|mygaming\.co\.za\/news\/wp\-content\/wallpapers\/|doubleclick\.net\/pfadx\/ugo\.gv\.1up\/|youtube\.com\/ptracking|youtube\-nocookie\.com\/gen_204|carbiz\.in\/affiliates\-and\-partners\/|videoplaza\.com\/proxy\/distributor\/|amazonaws\.com\/publishflow\/|ncrypt\.in\/images\/a\/|amazon\.com\/clog\/|amazonaws\.com\/ownlocal\-|cdn77\.org\/tags\/|any\.gs\/visitScript\/|livefyre\.com\/tracking\/|andyhoppe\.com\/count\/|xhamster\.com\/ads\/|allmyvideos\.net\/js\/ad_|fulltiltpoker\.com\/affiliates\/|static\.criteo\.com\/flash[^\w.%-]|ad\.mo\.doubleclick\.net\/dartproxy\/|questionmarket\.com\/static\/|thrixxx\.com\/affiliates\/|mtvnservices\.com\/metrics\/|doubleclick\.net\/pfadx\/mc\.channelnewsasia\.com[^\w.%-]|autotrader\.co\.za\/partners\/|static\.criteo\.com\/images[^\w.%-]|videowood\.tv\/pop2|video\.mediaset\.it\/polymediashowanalytics\/|rt\.com\/static\/img\/banners\/|static\.game\-state\.com\/images\/main\/alert\/replacement\/|supplyframe\.com\/partner\/|hostgator\.com\/~affiliat\/cgi\-bin\/affiliates\/|cloudfront\.net\/performable\/|filedownloader\.net\/design\/|softpedia\-static\.com\/images\/aff\/|doubleclick\.net\/pfadx\/nbcu\.nhl\.|doubleclick\.net\/pfadx\/nbcu\.nhl\/|doubleclick\.net\/pfadx\/intl\.sps\.com\/|doubleclick\.net\/pfadx\/blp\.video\/midroll|bristolairport\.co\.uk\/~\/media\/images\/brs\/blocks\/internal\-promo\-block\-300x250\/|sun\.com\/share\/metrics\/|femalefirst\.co\.uk\/widgets\/|pussycash\.com\/content\/banners\/|akamai\.net\/chartbeat\.|upsellit\.com\/custom\/|amazonaws\.com\/bo\-assets\/production\/banner_attachments\/|doubleclick\.net\/pfadx\/tmz\.video\.wb\.dart\/|addthis\.com\/at\/|banners\.friday\-ad\.co\.uk\/hpbanneruploads\/|doubleclick\.net\/pfadx\/bzj\.bizjournals\/|doubleclick\.net\/pfadx\/ndm\.tcm\/|bluehost\-cdn\.com\/media\/partner\/images\/|doubleclick\.net\/xbbe\/creative\/vast|phncdn\.com\/images\/banners\/|ad\.atdmt\.com\/m\/|techkeels\.com\/creatives\/|allanalpass\.com\/track\/|wishlistproducts\.com\/affiliatetools\/|theolympian\.com\/static\/images\/weathersponsor\/|doubleclick\.net\/pfadx\/miniclip\.midvideo\/|doubleclick\.net\/pfadx\/miniclip\.prevideo\/|doubleclick\.net\/adx\/wn\.nat\.|doubleclick\.net\/pfadx\/gn\.movieweb\.com\/|doubleclick\.net\/pfadx\/ddm\.ksl\/|urlcash\.org\/banners\/|betwaypartners\.com\/affiliate_media\/|doubleclick\.net\/pfadx\/ccr\.|tlavideo\.com\/affiliates\/|singlehop\.com\/affiliates\/|vidible\.tv\/placement\/vast\/|embed\.docstoc\.com\/Flash\.asmx\/StoreReffer|doubleclick\.net\/pfadx\/nbcu\.nbc\/|doubleclick\.net\/pfadx\/www\.tv3\.co\.nz|updatetube\.com\/iframes\/|publicbroadcasting\.net\/analytics\/|doubleclick\.net\/pfadx\/tmg\.telegraph\.|vitalmtb\.com\/assets\/vital\.aba\-|express\.de\/analytics\/|ebaystatic\.com\/aw\/signin\/ebay\-signin\-toyota\-|majorgeeks\.com\/images\/download_sd_|dx\.com\/affiliate\/|staticneo\.com\/neoassets\/iframes\/leaderboard_bottom\.|obox\-design\.com\/affiliate\-banners\/|browsershots\.org\/static\/images\/creative\/|bigrock\.in\/affiliate\/|share\-online\.biz\/affiliate\/|drift\.com\/track|hulkload\.com\/b\/|sulia\.com\/papi\/sulia_partner\.js\/|sitegiant\.my\/affiliate\/|imagecarry\.com\/down|mrc\.org\/sites\/default\/files\/uploads\/images\/Collusion_Banner|metromedia\.co\.za\/bannersys\/banners\/|dnsstuff\.com\/dnsmedia\/images\/ft\.banner\.|appinthestore\.com\/click\/|e\-tailwebstores\.com\/accounts\/default1\/banners\/|mail\.ru\/count\/|doubleclick\.net\/pfadx\/muzuoffsite\/|thebull\.com\.au\/admin\/uploads\/banners\/|debtconsolidationcare\.com\/affiliate\/tracker\/|twitch\.tv\/track\/|videos\.com\/click|beacons\.vessel\-static\.com\/xff|doubleclick\.net\/pfadx\/sugar\.poptv\/|doubleclick\.net\/pfadx\/ng\.videoplayer\/|celebstoner\.com\/assets\/components\/bdlistings\/uploads\/|doubleclick\.net\/pfadx\/CBS\.|couptopia\.com\/affiliate\/|flixcart\.com\/affiliate\/|infibeam\.com\/affiliate\/|lawdepot\.com\/affiliate\/|seedsman\.com\/affiliate\/|terra\.com\.br\/metrics\/|filez\.cutpaid\.com\/336v|goldmoney\.com\/~\/media\/Images\/Banners\/|mixpanel\.com\/track|apkmaza\.net\/wp\-content\/uploads\/|doubleclick\.net\/pfadx\/ssp\.kgtv\/|groupon\.com\/tracking|cnzz\.com\/stat\.|hentaistream\.com\/wp\-includes\/images\/bg\-|static\.twincdn\.com\/special\/script\.packed|static\.twincdn\.com\/special\/license\.packed|newoxfordreview\.org\/banners\/ad\-|doubleclick\.net\/adi\/|expertreviews\.co\.uk\/widget\/|theseblogs\.com\/visitScript\/|doubleclick\.net\/N2\/pfadx\/video\.wsj\.com\/|aerotime\.aero\/upload\/banner\/|doubleclick\.net\/pfadx\/nfl\.|brettterpstra\.com\/wp\-content\/uploads\/|bitbond\.com\/affiliate\-program\/|olark\.com\/track\/|chefkoch\.de\/counter|whozacunt\.com\/images\/banner_|google\-analytics\.com\/collect|static\.multiplayuk\.com\/images\/w\/w\-|epictv\.com\/sites\/default\/files\/290x400_|sdamgia\.ru\/img\/blockadblock_|h2porn\.com\/contents\/content_sources\/|thenude\.eu\/media\/mxg\/|glam\.com\/gad\/|morningstaronline\.co\.uk\/offsite\/progressive\-listings\/|ru4\.com\/click|doubleclick\.net\/pfadx\/csn\.|doubleclick\.net\/pfadx\/muzumain\/|mail\.ru\/counter|suite101\.com\/tracking\/|1movies\.to\/site\/videoroller|storage\.to\/affiliate\/|pedestrian\.tv\/_crunk\/wp\-content\/files_flutter\/|ad2links\.com\/js\/|lipsy\.co\.uk\/_assets\/images\/skin\/tracking\/|110\.45\.173\.103\/ad\/|theday\.com\/assets\/images\/sponsorlogos\/|gaccmidwest\.org\/uploads\/tx_bannermanagement\/|bruteforcesocialmedia\.com\/affiliates\/|wonderlabs\.com\/affiliate_pro\/banners\/|inhumanity\.com\/cdn\/affiliates\/|thesundaily\.my\/sites\/default\/files\/twinskyscrapers|ppc\-coach\.com\/jamaffiliates\/|slack\.com\/beacon\/|doubleclick\.net\/json|dealextreme\.com\/affiliate_upload\/|sacbee\.com\/static\/dealsaver\/|dnevnik\.si\/tracker\/|media\.domainking\.ng\/media\/|taboola\.com\/tb|bhaskar\.com\/ads\/|ehow\.com\/services\/jslogging\/log\/|kamcity\.com\/menu\/banners\/|americanfreepress\.net\/assets\/images\/Banner_|creativecdn\.com\/pix\/|pwpwpoker\.com\/images\/banners\/|yyv\.co\/track\/|russian\-dreams\.net\/static\/js\/|vivatube\.com\/upload\/banners\/|sapeople\.com\/wp\-content\/uploads\/wp\-banners\/|themis\-media\.com\/media\/global\/images\/cskins\/|inphonic\.com\/tracking\/|nspmotion\.com\/tracking\/|amazon\.com\/gp\/yourstore\/recs\/|accuradio\.com\/static\/track\/|zap2it\.com\/wp\-content\/themes\/overmind\/js\/zcode\-|worddictionary\.co\.uk\/static\/\/inpage\-affinity\/|sectools\.org\/shared\/images\/p\/|intercom\.io\/gtm_tracking\/|iradio\.ie\/assets\/img\/backgrounds\/|ibtimes\.com\/banner\/|dpbolvw\.net\/image\-|camwhores\.tv\/banners\/|anrdoezrs\.net\/image\-|knco\.com\/wp\-content\/uploads\/wpt\/|homoactive\.tv\/banner\/|yea\.xxx\/img\/creatives\/|inquirer\.net\/wp\-content\/themes\/news\/images\/wallpaper_|media\.enimgs\.net\/brand\/files\/escalatenetwork\/|petri\.co\.il\/wp\-content\/uploads\/banner1000x75_|petri\.co\.il\/wp\-content\/uploads\/banner700x475_|kontextr\.eu\/content\/track|dota\-trade\.com\/img\/branding_|vipbox\.tv\/js\/layer\-|thenude\.eu\/affiliates\/|plugins\.longtailvideo\.com\/yourlytics|dailyhome\.com\/leaderboard_banner|annistonstar\.com\/leaderboard_banner|proxysolutions\.net\/affiliates\/|whistleout\.com\.au\/imagelibrary\/ads\/wo_skin_|ians\.in\/iansad\/|thefind\.com\/page\/sizelog|djmag\.co\.uk\/sites\/default\/files\/takeover\/|itweb\.co\.za\/logos\/|hottubeclips\.com\/stxt\/banners\/|adm\.fwmrm\.net\/p\/mtvn_live\/|zambiz\.co\.zm\/banners\/|myanimelist\.cdn\-dena\.com\/images\/affiliates\/|wwe\.com\/sites\/all\/modules\/wwe\/wwe_analytics\/|freemoviestream\.xyz\/wp\-content\/uploads\/|204\.140\.25\.247\/ads\/|spot\.im\/yad\/|nmap\.org\/shared\/images\/p\/|foxadd\.com\/addon\/upixel\/|seclists\.org\/shared\/images\/p\/|usps\.com\/survey\/|desert\.ru\/tracking\/|omsnative\.de\/tracking\/|channel4\.com\/assets\/programmes\/images\/originals\/|c21media\.net\/wp\-content\/plugins\/sam\-images\/|expekt\.com\/affiliates\/|swurve\.com\/affiliates\/|brandcdn\.com\/pixel\/|axandra\.com\/affiliates\/|movie2kto\.ws\/popup|blissful\-sin\.com\/affiliates\/|singlemuslim\.com\/affiliates\/|mangaupdates\.com\/affiliates\/|bruteforceseo\.com\/affiliates\/|slide\.com\/tracker\/|graduateinjapan\.com\/affiliates\/|rbth\.ru\/widget\/|1320wils\.com\/assets\/images\/promo%20banner\/|ironsquid\.tv\/data\/uploads\/sponsors\/|itworld\.com\/slideshow\/iframe\/topimu\/|aftonbladet\.se\/blogportal\/view\/statistics|hqq\.watch\/js\/betterj\/|media\.complex\.com\/videos\/prerolls\/|doubleclick\.net\/adx\/tsg\.|tehrantimes\.com\/banner\/|ball2win\.com\/Affiliate\/|euphonik\.dj\/img\/sponsors\-|yahooapis\.com\/get\/Valueclick\/CapAnywhere\.getAnnotationCallback|relink\.us\/images\/|worldradio\.ch\/site_media\/banners\/|vator\.tv\/tracking\/|va\.tawk\.to\/log|putpat\.tv\/tracking|punterlink\.co\.uk\/images\/storage\/siteban|googlesyndication\.com\/ddm\/|salemwebnetwork\.com\/Stations\/images\/SiteWrapper\/|videovalis\.tv\/tracking\/|doubleclick\.net\/pfadx\/storm\.no\/|pixazza\.com\/track\/|sysomos\.com\/track\/|vpnarea\.com\/affiliate\/|luminate\.com\/track\/|picbucks\.com\/track\/|borrowlenses\.com\/affiliate\/|thereadystore\.com\/affiliate\/|doubleclick\.net\/pfadx\/trb\.|nation\.sc\/images\/banners\/|targetspot\.com\/track\/|turnsocial\.com\/track\/|b2w\.io\/event\/|getreading\.co\.uk\/static\/img\/bg_takeover_|youporn\.com\/watch_postroll\/|porn2blog\.com\/wp\-content\/banners\/|citeulike\.org\/static\/campaigns\/|optimum\.net\/utilities\/doubleclicktargeting|dyncdn\.celebuzz\.com\/assets\/|amazonaws\.com\/fstrk\.net\/|tsite\.jp\/static\/analytics\/|journal\-news\.net\/annoyingpopup\/|dailymail\.co\.uk\/tracking\/|djmag\.com\/sites\/default\/files\/takeover\/|ed\-protect\.org\/cdn\-cgi\/apps\/head\/|adyou\.me\/bug\/adcash|talkphotography\.co\.uk\/images\/externallogos\/banners\/|agitos\.de\/content\/track|preisvergleich\.de\/setcookie\/|theatm\.info\/images\/|mangareader\.net\/images\/800\-x\-100|saabsunited\.com\/wp\-content\/uploads\/180x460_|saabsunited\.com\/wp\-content\/uploads\/werbung\-|examiner\.com\/sites\/all\/modules\/custom\/ex_stats\/|dailymotion\.com\/logger\/|smn\-news\.com\/images\/banners\/|nfl\.com\/assets\/images\/hp\-poweredby\-|sextvx\.com\/static\/images\/tpd\-|radiotimes\.com\/assets\/images\/partners\/|casti\.tv\/adds\/|webdesignerdepot\.com\/wp\-content\/plugins\/md\-popup\/|reuters\.com\/tracker\/|ukcast\.tv\/adds\/|tamilwire\.org\/images\/banners3\/|toolslib\.net\/assets\/img\/a_dvt\/|live\-porn\.tv\/adds\/|xscores\.com\/livescore\/banners\/|visa\.com\/logging\/logEvent|go\.com\/stat\/|cloudfront\.net\/analyticsengine\/|distrowatch\.com\/images\/kokoku\/|getadblock\.com\/images\/adblock_banners\/|wikipedia\.org\/beacon\/|multiupload\.nl\/popunder\/|doubleclick\.net\/adx\/CBS\.|ovpn\.to\/ovpn\.to\/banner\/|chelsey\.co\.nz\/uploads\/Takeovers\/|richardroeper\.com\/assets\/banner\/|metroweekly\.com\/tools\/blog_add_visitor\/|babyblog\.ru\/pixel|skroutz\.gr\/analytics\/|ziffstatic\.com\/jst\/zdvtools\.|mightydeals\.com\/widget|myiplayer\.eu\/ad|camvideos\.tv\/tpd\.|freeporn\.to\/wpbanner\/|ximagehost\.org\/myman\.|conde\.io\/beacon|doubleclick\.net\/pfadx\/bet\.com\/|gamerant\.com\/ads\/|s\.holm\.ru\/stat\/|popeoftheplayers\.eu\/ad|playstation\.net\/event\/|topalternate\.com\/assets\/sponsored_links\-|abplive\.in\/analytics\/|avito\.ru\/stat\/|ejpress\.org\/img\/banners\/|swagmp3\.com\/cdn\-cgi\/pe\/|nijobfinder\.co\.uk\/affiliates\/|desperateseller\.co\.uk\/affiliates\/|amazonaws\.com\/initialize\/|arstechnica\.net\/public\/shared\/scripts\/da\-|sweed\.to\/affiliates\/|totallylayouts\.com\/online\-users\-counter\/|1page\.co\.za\/affiliate\/|timesinternet\.in\/ad\/|avira\.com\/site\/datatracking|insideyork\.co\.uk\/assets\/images\/sponsors\/|chaturbate\.com\/sitestats\/openwindow\/|videogame\.it\/a\/logview\/|safarinow\.com\/affiliate\-zone\/|urbanvelo\.org\/sidebarbanner\/|carambo\.la\/analytics\/|anti\-scam\.org\/abanners\/|watchuseek\.com\/media\/1900x220_|go2cdn\.org\/brand\/|bits\.wikimedia\.org\/geoiplookup|joblet\.jp\/javascripts\/|drom\.ru\/dummy\.|uk\-mkivs\.net\/uploads\/banners\/|guru99\.com\/images\/adblocker\/|cdn\.69games\.xxx\/common\/images\/friends\/|ziffstatic\.com\/jst\/zdsticky\.|kommersant\.uk\/banner_stats|webtv\.ws\/adds\/|gaccny\.com\/uploads\/tx_bannermanagement\/|ahk\-usa\.com\/uploads\/tx_bannermanagement\/|gaccwest\.com\/uploads\/tx_bannermanagement\/|gaccsouth\.com\/uploads\/tx_bannermanagement\/|trustedreviews\.com\/mobile\/widgets\/html\/promoted\-phones|flipkart\.com\/ajaxlog\/visitIdlog|text\-compare\.com\/media\/global_vision_banner_|lumfile\.com\/lumimage\/ourbanner\/|uploaded\.net\/img\/public\/|onescreen\.net\/os\/static\/pixels\/|lgoat\.com\/cdn\/amz_|geometria\.tv\/banners\/|vindicosuite\.com\/tracking\/|shinypics\.com\/blogbanner\/|thairath\.co\.th\/event\/|digitalsatellite\.tv\/banners\/|googlesyndication\.com\/simgad\/|eventful\.com\/tools\/click\/url|sciencecareers\.org\/widget\/|piano\.io\/tracker\/|clickandgo\.com\/booking\-form\-widget|porttechnology\.org\/images\/partners\/|tvducky\.com\/imgs\/graboid\.|tripadvisor\.com\/adp\/|appwork\.org\/hoster\/banner_|yotv\.co\/adds\/|thelodownny\.com\/leslog\/ads\/|nigeriafootball\.com\/img\/affiliate_|graboid\.com\/affiliates\/|uploading\.com\/static\/banners\/|mcvuk\.com\/static\/banners\/|pcmall\.co\.za\/affiliates\/|theleader\.info\/banner|amazonaws\.com\/btrb\-prd\-banners\/|adm24\.de\/hp_counter\/|traq\.li\/tracker\/|customerlobby\.com\/ctrack\-|eccie\.net\/buploads\/|vipstatic\.com\/mars\/|daily\-mail\.co\.zm\/images\/banners\/|peggo\.tv\/ad\/|yahoo\.com\/__darla\/|yahoo\.com\/darla\/|doubleclick\.net\/pfadx\/comedycentral\.|hqfooty\.tv\/ad|lowendbox\.com\/wp\-content\/themes\/leb\/banners\/|dmxleo\.dailymotion\.com\/cdn\/manifest\/video\/|alooma\.io\/track\/|sickipedia\.org\/static\/images\/banners\/|concealednation\.org\/sponsors\/|dailymail\.co\.uk\/i\/pix\/ebay\/|regnow\.img\.digitalriver\.com\/vendor\/37587\/ud_box|download\.bitdefender\.com\/resources\/media\/|doubleclick\.net\/adx\/wn\.loc\.|truck1\.eu\/_BANNERS_\/|develop\-online\.net\/static\/banners\/|justporno\.tv\/ad\/|early\-birds\.fr\/tracker\/|garrysmod\.org\/img\/sad\/|magnify\.net\/decor\/track\/|amy\.gs\/track\/|dyo\.gs\/track\/|ask\.com\/servlets\/ulog|getnzb\.com\/img\/partner\/banners\/|jakpost\.net\/jptracker\/|oasap\.com\/images\/affiliate\/|net\-parade\.it\/tracker\/|gamefront\.com\/wp\-content\/plugins\/tracker\/|kelkoo\.com\/kk_track|tvbrowser\.org\/logo_df_tvsponsor_|armenpress\.am\/static\/add\/|condenastdigital\.com\/content|eyetopics\.com\/content_images\/|doubleclick\.net\/pfadx\/ctv\.spacecast\/|chronicle\.lu\/images\/banners\/|youtube\.com\/user\/Blank|facebook\.com\/plugins\/|porntube\.com[^\w.%-](?=([\s\S]*?\/track))\1|facebook\.com[^\w.%-](?=([\s\S]*?\/tracking\.js))\2|bitgravity\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\3|youporn\.com[^\w.%-](?=([\s\S]*?\/tracker\.js))\4|clickfunnels\.com[^\w.%-](?=([\s\S]*?\/track))\5|ninemsn\.com\.au[^\w.%-](?=([\s\S]*?\.tracking\.udc\.))\6|cloudfront\.net(?=([\s\S]*?\/tracker\.js))\7|9msn\.com\.au[^\w.%-](?=([\s\S]*?\/tracking\/))\8|buzzfeed\.com[^\w.%-](?=([\s\S]*?\/tracker\.js))\9|reevoo\.com[^\w.%-](?=([\s\S]*?\/track\/))\10|gowatchit\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\11|skype\.com[^\w.%-](?=([\s\S]*?\/track_channel\.js))\12|svcs\.ebay\.com\/services\/search\/FindingService\/(?=([\s\S]*?[^\w.%-]affiliate\.tracking))\13|livefyre\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\14|forbes\.com[^\w.%-](?=([\s\S]*?\/track\.php))\15|msn\.com[^\w.%-](?=([\s\S]*?\/track\.js))\16|dealer\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\17|goadv\.com[^\w.%-](?=([\s\S]*?\/track\.js))\18|zdf\.de[^\w.%-](?=([\s\S]*?\/tracking))\19|dealer\.com[^\w.%-](?=([\s\S]*?\/tracker\/))\20|staticwhich\.co\.uk\/assets\/(?=([\s\S]*?\/track\.js))\21|marketingpilgrim\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/trackur\.com\-))\22|partypoker\.com[^\w.%-](?=([\s\S]*?\/tracking\-))\23|vectorstock\.com[^\w.%-](?=([\s\S]*?\/tracking))\24|doubleclick\.net[^\w.%-](?=([\s\S]*?\/trackimp\/))\25|euroleague\.tv[^\w.%-](?=([\s\S]*?\/tracking\.js))\26|azurewebsites\.net[^\w.%-](?=([\s\S]*?\/mnr\-mediametrie\-tracking\-))\27|ringostrack\.com[^\w.%-](?=([\s\S]*?\/amazon\-buy\.gif))\28|akamai\.net[^\w.%-](?=([\s\S]*?\/sitetracking\/))\29|lemde\.fr[^\w.%-](?=([\s\S]*?\/tracking\/))\30|comparis\.ch[^\w.%-](?=([\s\S]*?\/Tracking\/))\31|trackitdown\.net\/skins\/(?=([\s\S]*?_campaign\/))\32|fyre\.co[^\w.%-](?=([\s\S]*?\/tracking\/))\33|gazzettaobjects\.it[^\w.%-](?=([\s\S]*?\/tracking\/))\34|volkswagen\-italia\.it[^\w.%-](?=([\s\S]*?\/tracking\/))\35|smallcapnetwork\.com[^\w.%-](?=([\s\S]*?\/viewtracker\/))\36|chip\.de[^\w.%-](?=([\s\S]*?_tracking\/))\37|typepad\.com[^\w.%-](?=([\s\S]*?\/stats))\38|kat2\.biz\/(?=([\s\S]*?))\39|doubleclick\.net[^\w.%-](?=([\s\S]*?\/ad\/))\40|kickass2\.biz\/(?=([\s\S]*?))\41|adf\.ly\/(?=([\s\S]*?\.php))\42|doubleclick\.net[^\w.%-](?=([\s\S]*?\/adj\/))\43|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/adawe\-))\44|images\-amazon\.com[^\w.%-](?=([\s\S]*?\/Analytics\-))\45|r18\.com[^\w.%-](?=([\s\S]*?\/banner\/))\46|allmyvideos\.net\/(?=([\s\S]*?%))\47|allmyvideos\.net\/(?=([\s\S]*?))\48|hulkshare\.com[^\w.%-](?=([\s\S]*?\/adsmanager\.js))\49|images\-amazon\.com\/images\/(?=([\s\S]*?\/banner\/))\50|torrentproject\.ch\/(?=([\s\S]*?))\51|rackcdn\.com[^\w.%-](?=([\s\S]*?\/analytics\.js))\52|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/adaptvjw5\-))\53|freebunker\.com[^\w.%-](?=([\s\S]*?\/pops\.js))\54|openload\.co[^\w.%-](?=([\s\S]*?\/_))\55|213\.174\.140\.76[^\w.%-](?=([\s\S]*?\/js\/msn\.js))\56|amazonaws\.com[^\w.%-](?=([\s\S]*?\/pageviews))\57|thevideo\.me\/(?=([\s\S]*?\.php))\58|taboola\.com[^\w.%-](?=([\s\S]*?\/log\/))\59|liutilities\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\60|oload\.tv[^\w.%-](?=([\s\S]*?\/_))\61|xhcdn\.com[^\w.%-](?=([\s\S]*?\/ads_))\62|urlcash\.net\/random(?=([\s\S]*?\.php))\63|blogsmithmedia\.com[^\w.%-](?=([\s\S]*?\/amazon_))\64|quantserve\.com[^\w.%-](?=([\s\S]*?\.swf))\65|freebunker\.com[^\w.%-](?=([\s\S]*?\/oc\.js))\66|ifilm\.com\/website\/(?=([\s\S]*?_skin_))\67|kitguru\.net\/wp\-content\/uploads\/(?=([\s\S]*?\-Skin\.))\68|yimg\.com[^\w.%-](?=([\s\S]*?\/sponsored\.js))\69|bestofmedia\.com[^\w.%-](?=([\s\S]*?\/beacons\/))\70|videogamesblogger\.com[^\w.%-](?=([\s\S]*?\/scripts\/takeover\.js))\71|imgflare\.com[^\w.%-](?=([\s\S]*?\/splash\.php))\72|skypeassets\.com[^\w.%-](?=([\s\S]*?\/inclient\/))\73|thecatholicuniverse\.com[^\w.%-](?=([\s\S]*?\-ad\.))\74|i3investor\.com[^\w.%-](?=([\s\S]*?\/partner\/))\75|paypal\.com[^\w.%-](?=([\s\S]*?\/pixel\.gif))\76|static\.(?=([\s\S]*?\.criteo\.net\/js\/duplo[^\w.%-]))\77|thevideo\.me\/(?=([\s\S]*?_))\78|redtubefiles\.com[^\w.%-](?=([\s\S]*?\/banner\/))\79|meetlocals\.com[^\w.%-](?=([\s\S]*?popunder))\80|tumblr\.com[^\w.%-](?=([\s\S]*?\/sponsored_))\81|tumblr\.com[^\w.%-](?=([\s\S]*?_sponsored_))\82|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/ltas\-))\83|cloudzer\.net[^\w.%-](?=([\s\S]*?\/banner\/))\84|xhcdn\.com[^\w.%-](?=([\s\S]*?\/sponsor\-))\85|media\-imdb\.com[^\w.%-](?=([\s\S]*?\/affiliates\/))\86|widgetserver\.com[^\w.%-](?=([\s\S]*?\/image\.gif))\87|avg\.com[^\w.%-](?=([\s\S]*?\/stats\.js))\88|aolcdn\.com[^\w.%-](?=([\s\S]*?\/beacon\.min\.js))\89|facebook\.com\/ajax\/(?=([\s\S]*?\/log\.php))\90|static\.(?=([\s\S]*?\.criteo\.net\/images[^\w.%-]))\91|speedcafe\.com[^\w.%-](?=([\s\S]*?\-banner\-))\92|redtube\.com[^\w.%-](?=([\s\S]*?\/banner\/))\93|freebunker\.com[^\w.%-](?=([\s\S]*?\/raw\.js))\94|eweek\.com[^\w.%-](?=([\s\S]*?\/sponsored\-))\95|images\-amazon\.com\/images\/(?=([\s\S]*?\/ga\.js))\96|googleapis\.com[^\w.%-](?=([\s\S]*?\/gen_204))\97|imagefruit\.com[^\w.%-](?=([\s\S]*?\/pops\.js))\98|idg\.com\.au\/images\/(?=([\s\S]*?_promo))\99|thechive\.files\.wordpress\.com[^\w.%-](?=([\s\S]*?\-wallpaper\-))\100|yimg\.com[^\w.%-](?=([\s\S]*?\/flash\/promotions\/))\101|yimg\.com[^\w.%-](?=([\s\S]*?\/ywa\.js))\102|google\.com[^\w.%-](?=([\s\S]*?\/log))\103|arstechnica\.net[^\w.%-](?=([\s\S]*?\/sponsor\-))\104|googlesyndication\.com[^\w.%-](?=([\s\S]*?\/googlevideoadslibraryas3\.swf))\105|turner\.com[^\w.%-](?=([\s\S]*?\/ads\/))\106|widgetserver\.com[^\w.%-](?=([\s\S]*?\/quantcast\.swf))\107|adswizz\.com\/adswizz\/js\/SynchroClient(?=([\s\S]*?\.js))\108|armorgames\.com[^\w.%-](?=([\s\S]*?\/banners\/))\109|postaffiliatepro\.com[^\w.%-](?=([\s\S]*?\/banners\/))\110|24hourwristbands\.com\/(?=([\s\S]*?\.googleadservices\.com\/))\111|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/FME\-Red\-CAP\.jpg))\112|thecatholicuniverse\.com[^\w.%-](?=([\s\S]*?\-advert\-))\113|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/banner\.gif))\114|yimg\.com[^\w.%-](?=([\s\S]*?\/fairfax\/))\115|virginmedia\.com[^\w.%-](?=([\s\S]*?\/analytics\/))\116|adamvstheman\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/AVTM_banner\.jpg))\117|facebook\.com(?=([\s\S]*?\/impression\.php))\118|phpbb\.com[^\w.%-](?=([\s\S]*?\/images\/hosting\/hostmonster\-downloads\.gif))\119|imgbox\.com\/(?=([\s\S]*?\.html))\120|pimpandhost\.com\/static\/i\/(?=([\s\S]*?\-pah\.jpg))\121|johngaltfla\.com\/wordpress\/wp\-content\/uploads\/(?=([\s\S]*?\/TB2K_LOGO\.jpg))\122|johngaltfla\.com\/wordpress\/wp\-content\/uploads\/(?=([\s\S]*?\/jmcs_specaialbanner\.jpg))\123|financialsamurai\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/sliced\-alternative\-10000\.jpg))\124|gfi\.com\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\-BlogBanner))\125|cdmagurus\.com\/img\/(?=([\s\S]*?\.gif))\126|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/ibs\.orl\.news\/))\127|doubleclick\.net\/adx\/(?=([\s\S]*?\.NPR\.MUSIC\/))\128|amazonaws\.com[^\w.%-](?=([\s\S]*?\/Test_oPS_Script_Loads))\129|lfcimages\.com[^\w.%-](?=([\s\S]*?\/partner\-))\130|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/PW\-Ad\.jpg))\131|ibtimes\.com[^\w.%-](?=([\s\S]*?\/sponsor_))\132|newstatesman\.com\/sites\/all\/themes\/(?=([\s\S]*?_1280x2000\.))\133|nichepursuits\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/long\-tail\-pro\-banner\.gif))\134|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/team\.car\/))\135|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/team\.dal\/))\136|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/DeadwoodStove\-PW\.gif))\137|nfl\.com[^\w.%-](?=([\s\S]*?\/page\-background\-image\.jpg))\138|reddit\.com[^\w.%-](?=([\s\S]*?_sponsor\.png))\139|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/jihad\.jpg))\140|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.MTV\-Viacom\/))\141|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.NBCUNI\.COM\/))\142|cloudfront\.net(?=([\s\S]*?\/trk\.js))\143|queermenow\.net\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\-Banner))\144|opencurrency\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-aocs\-sidebar\-commodity\-bank\.png))\145|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/app\.ytpwatch\.))\146|copblock\.org\/wp\-content\/uploads\/(?=([\s\S]*?\/covert\-handcuff\-key\-AD\-))\147|berush\.com\/images\/(?=([\s\S]*?_semrush_))\148|marijuanapolitics\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/icbc1\.png))\149|marijuanapolitics\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/icbc2\.png))\150|thehealthcareblog\.com\/files\/(?=([\s\S]*?\/American\-Resident\-Project\-Logo\-))\151|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/ccr\.newyork\.))\152|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.NBCUNIVERSAL\-CNBC\/))\153|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/embed\.ytpwatch\.))\154|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Judge\-Lenny\-001\.jpg))\155|mrc\.org[^\w.%-](?=([\s\S]*?\/Collusion_Banner300x250\.jpg))\156|db\.com[^\w.%-](?=([\s\S]*?\/stats\.js))\157|thecommonsenseshow\.com\/siteupload\/(?=([\s\S]*?\/adsqmetals\.jpg))\158|nufc\.com[^\w.%-](?=([\s\S]*?\/The%20Gate_NUFC\.com%20banner_%2016\.8\.13\.gif))\159|allhiphop\.com\/site_resources\/ui\-images\/(?=([\s\S]*?\-conduit\-banner\.gif))\160|linkbird\.com\/static\/upload\/(?=([\s\S]*?\/banner\/))\161|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.NBCUNIVERSAL\/))\162|netbiscuits\.net[^\w.%-](?=([\s\S]*?\/analytics\/))\163|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Johnson\-Grow\-Lights\.gif))\164|telegraphindia\.com[^\w.%-](?=([\s\S]*?\/banners\/))\165|rghost\.ru\/download\/a\/(?=([\s\S]*?\/banner_download_))\166|pornsharing\.com\/App_Themes\/pornsharianew\/js\/adppornsharia(?=([\s\S]*?\.js))\167|pornsharing\.com\/App_Themes\/pornsharingnew\/js\/adppornsharia(?=([\s\S]*?\.js))\168|uflash\.tv[^\w.%-](?=([\s\S]*?\/affiliates\/))\169|flixster\.com[^\w.%-](?=([\s\S]*?\/analytics\.))\170|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/com\.ytpwatch\.))\171|cooksunited\.co\.uk\/counter(?=([\s\S]*?\.php))\172|queermenow\.net\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\/banner))\173|freebunker\.com[^\w.%-](?=([\s\S]*?\/layer\.js))\174|mydramalist\.info[^\w.%-](?=([\s\S]*?\/affiliates\/))\175|bitcoinreviewer\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/banner\-luckybit\.jpg))\176|thehealthcareblog\.com\/files\/(?=([\s\S]*?\/THCB\-Validic\-jpg\-opt\.jpg))\177|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/apmgoldmembership250x250\.jpg))\178|youku\.com[^\w.%-](?=([\s\S]*?\/click\.php))\179|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?_250x150\.png))\180|player\.screenwavemedia\.com[^\w.%-](?=([\s\S]*?\/ova\-jw\.swf))\181|yimg\.com\/cv\/(?=([\s\S]*?\/billboard\/))\182|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/team\.sd\/))\183|zoover\.(?=([\s\S]*?\/shared\/bannerpages\/darttagsbanner\.aspx))\184|purpleporno\.com\/pop(?=([\s\S]*?\.js))\185|data\.ninemsn\.com\.au\/(?=([\s\S]*?GetAdCalls))\186|drivereasy\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/sidebar\-DriverEasy\-buy\.jpg))\187|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?_300x400_))\188|totallylayouts\.com[^\w.%-](?=([\s\S]*?\/users\-online\-counter\/online\.js))\189|searchenginejournal\.com[^\w.%-](?=([\s\S]*?\/sponsored\-))\190|tipico\.(?=([\s\S]*?\/affiliate\/))\191|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?_Side_Banner\.))\192|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?_Side_Banner_))\193|preppersmallbiz\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/PSB\-Support\.jpg))\194|saf\.org\/wp\-content\/uploads\/(?=([\s\S]*?\/theGunMagbanner\.png))\195|activewin\.com[^\w.%-](?=([\s\S]*?\/blaze_static2\.gif))\196|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/180_350\.))\197|ragezone\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/HV\-banner\-300\-200\.jpg))\198|images\-pw\.secureserver\.net[^\w.%-](?=([\s\S]*?_))\199(?=([\s\S]*?\.))\200|starofmysore\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\-karbonn\.))\201|iimg\.in[^\w.%-](?=([\s\S]*?\/sponsor_))\202|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/ssp\.wews\/))\203|doubleclick\.net[^\w.%-](?=([\s\S]*?\/adi\/))\204|thecommonsenseshow\.com\/siteupload\/(?=([\s\S]*?\/nightvisionadnew\.jpg))\205|doubleclick\.net\/N2\/pfadx\/video\.(?=([\s\S]*?\.wsj\.com\/))\206|techinsider\.net\/wp\-content\/uploads\/(?=([\s\S]*?\-300x500\.))\207|ebaystatic\.com\/aw\/pics\/signin\/(?=([\s\S]*?_signInSkin_))\208|static\.ow\.ly[^\w.%-](?=([\s\S]*?\/click\.gz\.js))\209|structuredchannel\.com\/sw\/swchannel\/images\/MarketingAssets\/(?=([\s\S]*?\/BannerAd))\210|s\-assets\.tp\-cdn\.com\/widgets\/(?=([\s\S]*?\/vwid\/))\211(?=([\s\S]*?\.html))\212|adz\.lk[^\w.%-](?=([\s\S]*?_ad\.))\213|cardsharing\.info\/wp\-content\/uploads\/(?=([\s\S]*?\/ALLS\.jpg))\214|bestvpn\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/mosttrustedname_260x300_))\215|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.ABC\.com\/))\216|cannabisjobs\.us\/wp\-content\/uploads\/(?=([\s\S]*?\/OCWeedReview\.jpg))\217|saf\.org\/wp\-content\/uploads\/(?=([\s\S]*?\/women_guns192x50\.png))\218|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/tsepulveda\-1\.jpg))\219|doubleclick\.net\/(?=([\s\S]*?\/pfadx\/lin\.))\220|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.ESPN\/))\221|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.muzu\/))\222|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.BLIPTV\/))\223|doubleclick\.net\/pfadx\/(?=([\s\S]*?\/kidstv\/))\224|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/muzumain\/))\225|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.MCNONLINE\/))\226|doubleclick\.net\/pfadx\/(?=([\s\S]*?CBSINTERACTIVE\/))\227|upload\.ee\/image\/(?=([\s\S]*?\/B_descarga_tipo12\.gif))\228|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.VIACOMINTERNATIONAL\/))\229|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.WALTDISNEYINTERNETGROU\/))\230|grouponcdn\.com[^\w.%-](?=([\s\S]*?\/affiliate_widget\/))\231|malaysiabay\.org[^\w.%-](?=([\s\S]*?creatives\.php))\232|signup\.advance\.net[^\w.%-](?=([\s\S]*?affiliate))\233|libero\.it[^\w.%-](?=([\s\S]*?\/counter\.php))\234|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/gorillabanner728\.gif))\235|upcat\.custvox\.org\/survey\/(?=([\s\S]*?\/countOpen\.gif))\236|googlesyndication\.com[^\w.%-](?=([\s\S]*?\/domainpark\.cgi))\237|thepreparednessreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?_175x175\.jpg))\238|thepreparednessreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?_185x185\.jpg))\239|content\.ad\/Scripts\/widget(?=([\s\S]*?\.aspx))\240|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?\/sbt\.gif))\241|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/sensi2\.jpg))\242|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/cannafo\.jpg))\243|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/WeedSeedShop\.jpg))\244|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-250x250\.jpg))\245|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?_250x250\.jpg))\246|maciverse\.mangoco\.netdna\-cdn\.com[^\w.%-](?=([\s\S]*?banner))\247|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/dakine420\.png))\248|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/free_ross\.jpg))\249|sourcefed\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/netflix4\.jpg))\250|originalweedrecipes\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-Medium\.jpg))\251|saabsunited\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\-))\252|saabsunited\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\.))\253|saabsunited\.com\/wp\-content\/uploads\/(?=([\s\S]*?_banner_))\254|mypbrand\.com\/wp\-content\/uploads\/(?=([\s\S]*?banner))\255|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/scrogger\.gif))\256|lfgcomic\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/PageSkin_))\257|heyjackass\.com\/wp\-content\/uploads\/(?=([\s\S]*?_300x225_))\258|nextbigwhat\.com\/wp\-content\/uploads\/(?=([\s\S]*?ccavenue))\259|survivaltop50\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Survival215x150Link\.png))\260|hulkshare\.oncdn\.com[^\w.%-](?=([\s\S]*?\/removeads\.))\261|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/xbt\.jpg))\262|raysindex\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/dolmansept2012flash\.swf))\263|freedom\.com[^\w.%-](?=([\s\S]*?\/analytics\/))\264|video\.abc\.com[^\w.%-](?=([\s\S]*?\/promos\/))\265|gaystarnews\.com[^\w.%-](?=([\s\S]*?\-sponsor\.))\266|russiasexygirls\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/cb_))\267|capitolfax\.com\/wp\-content\/(?=([\s\S]*?ad\.))\268|ebaystatic\.com\/aw\/signin\/(?=([\s\S]*?_wallpaper_))\269|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/cmn_complextv\/))\270|morefree\.net\/wp\-content\/uploads\/(?=([\s\S]*?\/mauritanie\.gif))\271|thedailyblog\.co\.nz[^\w.%-](?=([\s\S]*?_Advert_))\272|static\.nfl\.com[^\w.%-](?=([\s\S]*?\-background\-))\273|vondroid\.com\/site\-img\/(?=([\s\S]*?\-adv\-ex\-))\274|walshfreedom\.com[^\w.%-](?=([\s\S]*?\/liberty\-luxury\.png))\275|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/728_))\276|wp\.com\/adnetsreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?banner))\277|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/xbt\-social\.png))\278|afcdn\.com[^\w.%-](?=([\s\S]*?\/ova\-jw\.swf))\279|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/allserviceslogo\.gif))\280|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/cloudbet_))\281|thecompassionchronicles\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\-))\282|thecompassionchronicles\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\.))\283|complexmedianetwork\.com[^\w.%-](?=([\s\S]*?\/toolbarlogo\.png))\284|eteknix\.com\/wp\-content\/uploads\/(?=([\s\S]*?Takeover))\285|uniblue\.com[^\w.%-](?=([\s\S]*?\/affiliates\/))\286|avito\.ru[^\w.%-](?=([\s\S]*?\/some\-pretty\-script\.js))\287|sify\.com[^\w.%-](?=([\s\S]*?\/gads_))\288|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.sevenload\.com_))\289|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/dynamic_banner_))\290|googlesyndication\.com[^\w.%-](?=([\s\S]*?\/click_to_buy\/))\291|pastime\.biz[^\w.%-](?=([\s\S]*?\/personalad))\292(?=([\s\S]*?\.jpg))\293|newsonjapan\.com[^\w.%-](?=([\s\S]*?\/banner\/))\294|galatta\.com[^\w.%-](?=([\s\S]*?\/banners\/))\295|ebaystatic\.com[^\w.%-](?=([\s\S]*?\/motorswidgetsv2\.swf))\296|thejointblog\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-235x))\297|thepreparednessreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/250x125\-))\298|capitolfax\.com\/wp\-content\/(?=([\s\S]*?Ad_))\299|rapidfiledownload\.com[^\w.%-](?=([\s\S]*?\/btn\-input\-download\.png))\300|lego\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\301|srwww1\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\302|allmovie\.com[^\w.%-](?=([\s\S]*?\/affiliate_))\303|tigerdirect\.com[^\w.%-](?=([\s\S]*?\/affiliate_))\304|sfstatic\.com[^\w.%-](?=([\s\S]*?\/js\/fl\.js))\305|dailyanimation\.studio[^\w.%-](?=([\s\S]*?\/banners\.))\306|russiasexygirls\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/727x90))\307|dailyherald\.com[^\w.%-](?=([\s\S]*?\/contextual\.js))\308|upickem\.net[^\w.%-](?=([\s\S]*?\/affiliates\/))\309|foxandhoundsdaily\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-AD\.gif))\310|videoly\.co[^\w.%-](?=([\s\S]*?\/event\/))\311|talktalk\.co\.uk[^\w.%-](?=([\s\S]*?\/log\.html))\312|sillusions\.ws[^\w.%-](?=([\s\S]*?\/vpn\-banner\.gif))\313|seedr\.ru[^\w.%-](?=([\s\S]*?\/stats\/))\314|gmstatic\.net[^\w.%-](?=([\s\S]*?\/amazonbadge\.png))\315|guns\.ru[^\w.%-](?=([\s\S]*?\/banners\/))\316|edgecastcdn\.net[^\w.%-](?=([\s\S]*?\.barstoolsports\.com\/wp\-content\/banners\/))\317|947\.co\.za[^\w.%-](?=([\s\S]*?\-branding\.))\318|llnwd\.net\/o28\/assets\/(?=([\s\S]*?\-sponsored\-))\319|lawprofessorblogs\.com\/responsive\-template\/(?=([\s\S]*?advert\.))\320|between\-legs\.com[^\w.%-](?=([\s\S]*?\/banners\/))\321|dailyblogtips\.com\/wp\-content\/uploads\/(?=([\s\S]*?\.gif))\322|doubleclick\.net\/adx\/(?=([\s\S]*?\.NPR\/))\323|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.nbc\.com\/))\324|zombiegamer\.co\.za\/wp\-content\/uploads\/(?=([\s\S]*?\-skin\-))\325|allposters\.com[^\w.%-](?=([\s\S]*?\/banners\/))\326|xrad\.io[^\w.%-](?=([\s\S]*?\/hotspots\/))\327|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-180x350\.))\328|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/180x350\.))\329|dada\.net[^\w.%-](?=([\s\S]*?\/nedstat_sitestat\.js))\330|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/billpayhelp2\.png))\331|digitaltveurope\.net\/wp\-content\/uploads\/(?=([\s\S]*?_wallpaper_))\332|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?_270x312\.))\333|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?_1170x120\.))\334|ebaystatic\.com[^\w.%-](?=([\s\S]*?\/agof_survey_))\335|totallylayouts\.com[^\w.%-](?=([\s\S]*?\/visitor\-counter\/counter\.js))\336|ebaystatic\.com[^\w.%-](?=([\s\S]*?\/iam_))\337|wired\.com\/images\/xrail\/(?=([\s\S]*?\/samsung_layar_))\338|dnsstuff\.com\/dnsmedia\/images\/(?=([\s\S]*?_banner\.jpg))\339|atlantafalcons\.com\/wp\-content\/(?=([\s\S]*?\/metrics\.js))\340|hollyscoop\.com\/sites\/(?=([\s\S]*?\/skins\/))\341|javascript\-coder\.com[^\w.%-](?=([\s\S]*?\/make\-form\-without\-coding\.png))\342|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/ccn\.png))\343|aolcdn\.com\/os\/music\/img\/(?=([\s\S]*?\-skin\.jpg))\344|madamenoire\.com\/wp\-content\/(?=([\s\S]*?_Reskin\-))\345|punch\.cdn\.ng[^\w.%-](?=([\s\S]*?\/wp\-banners\/))\346|agendize\.com[^\w.%-](?=([\s\S]*?\/counts\.jsp))\347|themittani\.com\/sites\/(?=([\s\S]*?\-skin))\348|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/helix\.gif))\349|tremormedia\.com\/embed\/js\/(?=([\s\S]*?_ads\.js))\350|vertical\-n\.de\/scripts\/(?=([\s\S]*?\/immer_oben\.js))\351|verticalnetwork\.de\/scripts\/(?=([\s\S]*?\/immer_oben\.js))\352|rawstory\.com[^\w.%-](?=([\s\S]*?\/ads\/))\353|islamicity\.org[^\w.%-](?=([\s\S]*?\/sponsorship\-))\354|thessdreview\.com[^\w.%-](?=([\s\S]*?\/owc\-full\-banner\.jpg))\355|celebstoner\.com\/assets\/images\/img\/sidebar\/(?=([\s\S]*?\/freedomleaf\.png))\356|paypalobjects\.com[^\w.%-](?=([\s\S]*?\/pixel\.gif))\357|nbr\.co\.nz[^\w.%-](?=([\s\S]*?\-WingBanner_))\358|googlesyndication\.com[^\w.%-](?=([\s\S]*?\/simgad\/))\359|bassmaster\.com[^\w.%-](?=([\s\S]*?\/premier_sponsor_logo\/))\360|adprimemedia\.com[^\w.%-](?=([\s\S]*?\/video_report\/videoReport\.php))\361|adprimemedia\.com[^\w.%-](?=([\s\S]*?\/video_report\/attemptAdReport\.php))\362|nature\.com[^\w.%-](?=([\s\S]*?\/marker\-file\.nocache))\363|pocketnow\.com(?=([\s\S]*?\/embeded\-adtional\-content\/))\364|justsomething\.co\/wp\-content\/uploads\/(?=([\s\S]*?\-250x250\.))\365|dell\.com\/images\/global\/js\/s_metrics(?=([\s\S]*?\.js))\366|sella\.co\.nz[^\w.%-](?=([\s\S]*?\/sella_stats_))\367|mmoculture\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-background\-))\368|cbs\.com\/assets\/js\/(?=([\s\S]*?AdvCookie\.js))\369|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?_banner\.))\370|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/7281\.gif))\371|ebaystatic\.com[^\w.%-](?=([\s\S]*?\/ScandalJS\-))\372|ebaystatic\.com[^\w.%-](?=([\s\S]*?\/ScandalSupportGFA\-))\373|amazonaws\.com[^\w.%-](?=([\s\S]*?\/player_request_))\374(?=([\s\S]*?\/get_affiliate_))\375|kvcr\.org[^\w.%-](?=([\s\S]*?\/sponsors\/))\376|star883\.org[^\w.%-](?=([\s\S]*?\/sponsors\.))\377|freecycle\.org[^\w.%-](?=([\s\S]*?\/sponsors\/))\378|sexmo\.org\/static\/images\/(?=([\s\S]*?_banners_))\379|aviationweek\.com[^\w.%-](?=([\s\S]*?\/leader_board\.htm))\380|ws\.amazon\.(?=([\s\S]*?\/widgets\/))\381|jdownloader\.org[^\w.%-](?=([\s\S]*?\/smbanner\.png))\382|spotify\.com[^\w.%-](?=([\s\S]*?\/metric))\383|nymag\.com[^\w.%-](?=([\s\S]*?\/analytics\.js))\384|hwscdn\.com[^\w.%-](?=([\s\S]*?\/brands_analytics\.js))\385|mrskincdn\.com[^\w.%-](?=([\s\S]*?\/flash\/aff\/))\386|xxxgames\.biz[^\w.%-](?=([\s\S]*?\/sponsors\/))\387|armorgames\.com[^\w.%-](?=([\s\S]*?\/siteskin\.css))\388|newsday\.co\.zw[^\w.%-](?=([\s\S]*?\-advert\.))\389|bitcoinist\.net\/wp\-content\/uploads\/(?=([\s\S]*?_250x250_))\390|dreamscene\.org[^\w.%-](?=([\s\S]*?_Banner\.))\391)/i;
var bad_da_hostpath_regex_flag = 972 > 0 ? true : false;  // test for non-zero number of rules
    
// 162 rules as an efficient NFA RegExp:
var bad_da_RegExp = /^(?:[\w-]+\.)*?(?:porntube\.com\/ads$|ads\.|adv\.|1337x\.to[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|banner\.|banners\.|torrentz2\.eu[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|synad\.|erotikdeal\.com\/\?ref=|affiliate\.|affiliates\.|cloudfront\.net\/\?a=|quantserve\.com\/pixel;|cursecdn\.com\/shared\-assets\/current\/anchor\.js\?id=|yahoo\.com\/p\.gif;|cloudfront\.net\/\?tid=|bluehost\.com\/web\-hosting\/domaincheckapi\/\?affiliate=|kickass2\.st[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|katcr\.co[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|sweed\.to\/\?pid=|qualtrics\.com\/WRSiteInterceptEngine\/\?Q_Impress=|bittorrent\.am[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|nowwatchtvlive\.ws[^\w.%-]\$csp=script\-src 'self' |ad\.atdmt\.com\/i\/go;|torrentdownloads\.me[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|x1337x\.ws[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|uploadproper\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|oddschecker\.com\/clickout\.htm\?type=takeover\-|tube911\.com\/scj\/cgi\/out\.php\?scheme_id=|movies\.askjolene\.com\/c64\?clickid=|ipornia\.com\/scj\/cgi\/out\.php\?scheme_id=|watchsomuch\.info[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|api\.ticketnetwork\.com\/Events\/TopSelling\/domain=nytimes\.com|torrentdownload\.ch[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|totalporn\.com\/videos\/tracking\/\?url=|torrentfunk2\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|pirateiro\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|magnetdl\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|kommersant\.ru\/a\.asp\?p=|limetorrents\.info[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|watchfree\.to\/download\.php\?type=1&title=|t\-online\.de[^\w.%-](?=([\s\S]*?\/stats\.js\?track=))\1|tinypic\.com\/api\.php\?(?=([\s\S]*?&action=track))\2|fantasti\.cc[^\w.%-](?=([\s\S]*?\?ad=))\3|casino\-x\.com[^\w.%-](?=([\s\S]*?\?partner=))\4|allmyvideos\.net\/(?=([\s\S]*?=))\5|quantserve\.com[^\w.%-](?=([\s\S]*?[^\w.%-]a=))\6|exashare\.com[^\w.%-](?=([\s\S]*?&h=))\7|blacklistednews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\8|ad\.atdmt\.com\/i\/(?=([\s\S]*?=))\9|swatchseries\.to[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\10|acidcow\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\11|thevideo\.me\/(?=([\s\S]*?\:))\12|1movies\.is[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' 'unsafe\-eval' data\: (?=([\s\S]*?\.jwpcdn\.com ))\13(?=([\s\S]*?\.gstatic\.com ))\14(?=([\s\S]*?\.googletagmanager\.com ))\15(?=([\s\S]*?\.addthis\.com ))\16(?=([\s\S]*?\.google\.com))\17|iyfsearch\.com[^\w.%-](?=([\s\S]*?&pid=))\18|uptobox\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline' ))\19(?=([\s\S]*?\.gstatic\.com ))\20(?=([\s\S]*?\.google\.com ))\21(?=([\s\S]*?\.googleapis\.com))\22|phonearena\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\23|2hot4fb\.com\/img\/(?=([\s\S]*?\.gif\?r=))\24|watchcartoononline\.io[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\25|merriam\-webster\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\26|flirt4free\.com[^\w.%-](?=([\s\S]*?&utm_campaign))\27|plista\.com\/widgetdata\.php\?(?=([\s\S]*?%22pictureads%22%7D))\28|pornsharing\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' 'unsafe\-eval' data\: (?=([\s\S]*?\.google\.com ))\29(?=([\s\S]*?\.gstatic\.com ))\30(?=([\s\S]*?\.google\-analytics\.com))\31|wikia\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline' 'unsafe\-eval' ))\32(?=([\s\S]*?\.jwpsrv\.com ))\33(?=([\s\S]*?\.jwplayer\.com))\34|shortcuts\.search\.yahoo\.com[^\w.%-](?=([\s\S]*?&callback=yahoo\.shortcuts\.utils\.setdittoadcontents&))\35|unblocked\.win[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\36|sobusygirls\.fr[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-eval'))\37|media\.campartner\.com\/index\.php\?cpID=(?=([\s\S]*?&cpMID=))\38|eafyfsuh\.net[^\w.%-](?=([\s\S]*?\/\?name=))\39|videogamesblogger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\40(?=([\s\S]*?\.gstatic\.com ))\41(?=([\s\S]*?\.google\.com ))\42(?=([\s\S]*?\.googleapis\.com ))\43(?=([\s\S]*?\.playwire\.com ))\44(?=([\s\S]*?\.facebook\.com ))\45(?=([\s\S]*?\.bootstrapcdn\.com ))\46(?=([\s\S]*?\.twitter\.com ))\47(?=([\s\S]*?\.spot\.im))\48|rover\.ebay\.com\.au[^\w.%-](?=([\s\S]*?&cguid=))\49|bighealthreport\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\50(?=([\s\S]*?\.gstatic\.com ))\51(?=([\s\S]*?\.google\.com ))\52(?=([\s\S]*?\.googleapis\.com ))\53(?=([\s\S]*?\.playwire\.com ))\54(?=([\s\S]*?\.facebook\.com ))\55(?=([\s\S]*?\.bootstrapcdn\.com ))\56(?=([\s\S]*?\.yimg\.com))\57|postimg\.cc\/image\/\$csp=script\-src 'self' (?=([\s\S]*? data\: blob\: 'unsafe\-eval'))\58|get\.(?=([\s\S]*?\.website\/static\/get\-js\?stid=))\59|linkbucks\.com[^\w.%-](?=([\s\S]*?\/\?))\60(?=([\s\S]*?=))\61|lijit\.com\/blog_wijits\?(?=([\s\S]*?=trakr&))\62|solarmovie\.one[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\63|pockettactics\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\64|btkitty\.pet[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' (?=([\s\S]*?\.cloudflare\.com ))\65(?=([\s\S]*?\.googleapis\.com ))\66(?=([\s\S]*?\.jsdelivr\.net))\67|torrentz\.eu\/search(?=([\s\S]*?=))\68|facebook\.com\/(?=([\s\S]*?\/plugins\/send_to_messenger\.php\?app_id=))\69|answerology\.com\/index\.aspx\?(?=([\s\S]*?=ads\.ascx))\70|freehostedscripts\.net[^\w.%-](?=([\s\S]*?\.php\?site=))\71(?=([\s\S]*?&s=))\72(?=([\s\S]*?&h=))\73|shopify\.com\/(?=([\s\S]*?\/page\?))\74(?=([\s\S]*?&eventType=))\75|ifly\.com\/trip\-plan\/ifly\-trip\?(?=([\s\S]*?&ad=))\76|doubleclick\.net\/pfadx\/(?=([\s\S]*?adcat=))\77|tipico\.(?=([\s\S]*?\?affiliateId=))\78|viralnova\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\79(?=([\s\S]*?\.gstatic\.com ))\80(?=([\s\S]*?\.google\.com ))\81(?=([\s\S]*?\.googleapis\.com ))\82(?=([\s\S]*?\.playwire\.com ))\83(?=([\s\S]*?\.facebook\.com ))\84(?=([\s\S]*?\.bootstrapcdn\.com))\85|waybig\.com\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\?pas=))\86|bulletsfirst\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\87(?=([\s\S]*?\.gstatic\.com ))\88(?=([\s\S]*?\.google\.com ))\89(?=([\s\S]*?\.googleapis\.com ))\90(?=([\s\S]*?\.playwire\.com ))\91(?=([\s\S]*?\.facebook\.com ))\92(?=([\s\S]*?\.bootstrapcdn\.com))\93|barbwire\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\94(?=([\s\S]*?\.gstatic\.com ))\95(?=([\s\S]*?\.google\.com ))\96(?=([\s\S]*?\.googleapis\.com ))\97(?=([\s\S]*?\.playwire\.com ))\98(?=([\s\S]*?\.facebook\.com ))\99(?=([\s\S]*?\.bootstrapcdn\.com))\100|thehayride\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\101(?=([\s\S]*?\.gstatic\.com ))\102(?=([\s\S]*?\.google\.com ))\103(?=([\s\S]*?\.googleapis\.com ))\104(?=([\s\S]*?\.playwire\.com ))\105(?=([\s\S]*?\.facebook\.com ))\106(?=([\s\S]*?\.bootstrapcdn\.com))\107|wakingtimes\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\108(?=([\s\S]*?\.gstatic\.com ))\109(?=([\s\S]*?\.google\.com ))\110(?=([\s\S]*?\.googleapis\.com ))\111(?=([\s\S]*?\.playwire\.com ))\112(?=([\s\S]*?\.facebook\.com ))\113(?=([\s\S]*?\.bootstrapcdn\.com))\114|activistpost\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\115(?=([\s\S]*?\.gstatic\.com ))\116(?=([\s\S]*?\.google\.com ))\117(?=([\s\S]*?\.googleapis\.com ))\118(?=([\s\S]*?\.playwire\.com ))\119(?=([\s\S]*?\.facebook\.com ))\120(?=([\s\S]*?\.bootstrapcdn\.com))\121|allthingsvegas\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\122(?=([\s\S]*?\.gstatic\.com ))\123(?=([\s\S]*?\.google\.com ))\124(?=([\s\S]*?\.googleapis\.com ))\125(?=([\s\S]*?\.playwire\.com ))\126(?=([\s\S]*?\.facebook\.com ))\127(?=([\s\S]*?\.bootstrapcdn\.com))\128|survivalnation\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\129(?=([\s\S]*?\.gstatic\.com ))\130(?=([\s\S]*?\.google\.com ))\131(?=([\s\S]*?\.googleapis\.com ))\132(?=([\s\S]*?\.playwire\.com ))\133(?=([\s\S]*?\.facebook\.com ))\134(?=([\s\S]*?\.bootstrapcdn\.com))\135|thelibertydaily\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\136(?=([\s\S]*?\.gstatic\.com ))\137(?=([\s\S]*?\.google\.com ))\138(?=([\s\S]*?\.googleapis\.com ))\139(?=([\s\S]*?\.playwire\.com ))\140(?=([\s\S]*?\.facebook\.com ))\141(?=([\s\S]*?\.bootstrapcdn\.com))\142|visiontoamerica\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\143(?=([\s\S]*?\.gstatic\.com ))\144(?=([\s\S]*?\.google\.com ))\145(?=([\s\S]*?\.googleapis\.com ))\146(?=([\s\S]*?\.playwire\.com ))\147(?=([\s\S]*?\.facebook\.com ))\148(?=([\s\S]*?\.bootstrapcdn\.com))\149|comicallyincorrect\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\150(?=([\s\S]*?\.gstatic\.com ))\151(?=([\s\S]*?\.google\.com ))\152(?=([\s\S]*?\.googleapis\.com ))\153(?=([\s\S]*?\.playwire\.com ))\154(?=([\s\S]*?\.facebook\.com ))\155(?=([\s\S]*?\.bootstrapcdn\.com))\156|americasfreedomfighters\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\157(?=([\s\S]*?\.gstatic\.com ))\158(?=([\s\S]*?\.google\.com ))\159(?=([\s\S]*?\.googleapis\.com ))\160(?=([\s\S]*?\.playwire\.com ))\161(?=([\s\S]*?\.facebook\.com ))\162(?=([\s\S]*?\.bootstrapcdn\.com))\163|yifyddl\.movie[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' (?=([\s\S]*?\.googleapis\.com))\164|tipico\.com[^\w.%-](?=([\s\S]*?\?affiliateid=))\165|hop\.clickbank\.net\/(?=([\s\S]*?&transaction_id=))\166(?=([\s\S]*?&offer_id=))\167|onion\.ly[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\168|miniurls\.co[^\w.%-](?=([\s\S]*?\?ref=))\169|freebeacon\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\170|extremetech\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\171|moviewatcher\.is[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\172|computerarts\.co\.uk\/(?=([\s\S]*?\.php\?cmd=site\-stats))\173|freean\.us[^\w.%-](?=([\s\S]*?\?ref=))\174|prox4you\.pw[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\175|unblockall\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\176|cloudfront\.net(?=([\s\S]*?\/sp\.js$))\177|unblocked\.pet[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\178|machinenoveltranslation\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\179|fullmatchesandshows\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\180|nintendoeverything\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\181|textsfromlastnight\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\182|powerofpositivity\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\183|talkwithstranger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\184|readliverpoolfc\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\185|androidcentral\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\186|roadracerunner\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\187|tetrisfriends\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\188|thisisfutbol\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\189|almasdarnews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\190|colourlovers\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\191|convertfiles\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\192|investopedia\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\193|skidrowcrack\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\194|sportspickle\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\195|hiphopearly\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\196|readarsenal\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\197|kshowonline\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\198|moneyversed\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\199|thehornnews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\200|torrentfunk\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\201|videocelts\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\202|britannica\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\203|csgolounge\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\204|grammarist\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\205|healthline\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\206|tworeddots\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\207|wuxiaworld\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\208|kiplinger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\209|readmng\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\210|trifind\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\211|vidmax\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\212|debka\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\213|amazon\.com\/gp\/(?=([\s\S]*?&linkCode))\214|123unblock\.xyz[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\215|clickbank\.net\/(?=([\s\S]*?offer_id=))\216|widgets\.itunes\.apple\.com[^\w.%-](?=([\s\S]*?&affiliate_id=))\217|skyscanner\.(?=([\s\S]*?\/slipstream\/applog$))\218|winit\.winchristmas\.co\.uk[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\219|biology\-online\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\220|broadwayworld\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\221|cts\.tradepub\.com\/cts4\/\?ptnr=(?=([\s\S]*?&tm=))\222|ancient\-origins\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\223|asheepnomore\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\224|campussports\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\225|toptenz\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\226)/i;
var bad_da_regex_flag = 162 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_url_parts_RegExp = /^$/;
var good_url_parts_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 2731 rules as an efficient NFA RegExp:
var bad_url_parts_RegExp = /(?:\/adcontent\.|\/adsys\/|\/adserver\.|\/pp\-ad\.|\.com\/ads\?|\?getad=&|\.online\/ads\/|\/online\/ads\/|\/img\/adv\.|\/img\/adv\/|\/expandable_ad\?|\/online\-ad_|_online_ad\.|\/homepage\-ads\/|\/homepage\/ads\/|\/ad\-engine\.|\/ad_engine\?|\/static\/tracking\/|\-online\-advert\.|\-web\-ad\-|\/web\-ad_|\-leaderboard\-ad\-|\/leaderboard_ad\.|\/leaderboard_ad\/|\/imgad\.|\/imgad\?|\/iframead\.|\/iframead\/|\/contentad\/|\/contentad$|\-ad\-content\/|\/ad\/content\/|\/ad_content\.|\/adcontent\/|\/ad\-image\.|\/ad\/image\/|\/ad_image\.|\/ad\-images\/|\/ad\/images\/|\/ad_images\/|\/webad\?|_webad\.|\/superads_|\-iframe\-ad\.|\/iframe\-ad\.|\/iframe\-ad\/|\/iframe\-ad\?|\/iframe\.ad\/|\/iframe\/ad\/|\/iframe\/ad_|\/iframe_ad\.|\/iframe_ad\?|\-content\-ad\-|\-content\-ad\.|\/content\/ad\/|\/content\/ad_|\/content_ad\.|_content_ad\.|\/adplugin\.|\/adplugin\/|\/adplugin_|\/web\-analytics\.|\/web_analytics\/|\/video\-ad\.|\/video\/ad\/|\/video_ad\.|\.com\/video\-ad\-|_js\/ads\.js|\-ad_leaderboard\/|\/ad\-leaderboard\.|\/ad\/leaderboard\.|\/ad_leaderboard\.|\/ad_leaderboard\/|=ad\-leaderboard\-|=adcenter&|\/popad$|\.adriver\.|\/adriver\.|\/adriver_|\/_img\/ad_|\/img\/_ad\.|\/img\/ad\-|\/img\/ad\.|\/img\/ad\/|\/img_ad\/|\/assets\/js\/ad\.|\.com\/\?adv=|\/t\/event\.js\?|\/pop2\.js$|\-ad\-iframe\.|\-ad\-iframe\/|\-ad\/iframe\/|\/ad\-iframe\-|\/ad\-iframe\.|\/ad\-iframe\?|\/ad\/iframe\.|\/ad\/iframe\/|\/ad\?iframe_|\/ad_iframe\.|\/ad_iframe_|=ad_iframe&|=ad_iframe_|\/xtclicks\.|\/xtclicks_|\/ad\.php$|\/bottom\-ads\.|_search\/ads\.js|\-text\-ads\.|\/expandable_ad\.php|\/bg\/ads\/|\/post\/ads\/|\/ad132m\/|\.net\/ad\/|\-show\-ads\.|\/show\-ads\.|\-top\-ads\.|\/top\-ads\.|\/ad_pop\.php\?|\/footer\-ads\/|\/inc\/ads\/|\/adclick\.|\-ads\-iframe\.|\/ads\/iframe|\/ads_iframe\.|\-iframe\-ads\/|\/iframe\-ads\/|\/iframe\/ads\/|\/afs\/ads\/|\/remove\-ads\.|\.co\/ads\/|\/user\/ads\?|\.no\/ads\/|\/special\-ads\/|\-article\-ads\-|\/pc\/ads\.|\/mobile\-ads\/|\/js\/ads\-|\/js\/ads\.|\/js\/ads_|\/dynamic\/ads\/|\/i\/ads\/|\-video\-ads\/|\/video\-ads\/|\/video\.ads\.|\/video\/ads\/|\/vast\/ads\-|\/td\-ads\-|\/mini\-ads\/|\/cms\/ads\/|\/ads\.cms|\/ads\/html\/|\/modules\/ads\/|\/player\/ads\.|\/player\/ads\/|\/ext\/ads\/|\/default\/ads\/|\/left\-ads\.|\/external\/ads\/|\/delivery\.ads\.|\/responsive\-ads\.|\/ads\/targeting\.|\/ads\/click\?|\/ads_reporting\/|\/custom\/ads|\/ad\?count=|\/ad_count\.|\/showads\/|\/ad\/logo\/|\/ads\/async\/|\/house\-ads\/|\/media\/ad\/|\/sidebar\-ads\/|_track\/ad\/|\/analytics\.gif\?|\/ads12\.|\-adskin\.|\/adskin\/|\/ads\.htm|\/adsetup\.|\/adsetup_|\/adsframe\.|\/ad\?sponsor=|\/image\/ads\/|\/image\/ads_|\.ads\.css|\/ads\.css|\/adsdaq_|\/click\?adv=|&program=revshare&|\-peel\-ads\-|\/blogad\.|\/realmedia\/ads\/|\/adbanners\/|\/popupads\.|\/click\.track\?|\/banner\-adv\-|\/banner\/adv\/|\/banner\/adv_|\.link\/ads\/|\/lazy\-ads\-|\/lazy\-ads\.|\/adlog\.|\/adsrv\.|\/adsrv\/|\/ads\.php|\/ads_php\/|\/google_tag\.|\/google_tag\/|\/ad_video\.htm|\/partner\.ads\.|\/ads\/square\-|\/ads\/square\.|\/adsys\.|\/aff_ad\?|\/new\-ads\/|\/new\/ads\/|\/plugins\/ads\-|\/plugins\/ads\/|\/log\/ad\-|\/log_ad\?|\/ads\/text\/|\/ads_text_|\/sponsored_ad\.|\/sponsored_ad\/|\/ads\.js\.|\/ads\.js\/|\/ads\.js\?|\/ads\/js\.|\/ads\/js\/|\/ads\/js_|\/video\-ad\-overlay\.|\/ads8\.|\/ads8\/|\/adsjs\.|\/adsjs\/|&adcount=|\/adstop\.|\/adstop_|\.ads1\-|\.ads1\.|\/ads1\.|\/ads1\/|\/blog\/ads\/|\/flash\-ads\.|\/flash\-ads\/|\/flash\/ads\/|\-adbanner\.|\.adbanner\.|\/adbanner\.|\/adbanner\/|\/adbanner_|=adbanner_|\/adpartner\.|\?adpartner=|\-adsonar\.|\/adsonar\.|\/home\/ads\-|\/home\/ads\/|\/home\/ads_|\/s_ad\.aspx\?|=popunders&|\/adClick\/|\/adClick\?|\/ads\-new\.|\/ads_new\.|\/ads_new\/|\/ad\/js\/pushdown\.|\/bin\/stats\?|\.adserve\.|\/adserve\-|\/adserve\.|\/adserve\/|\/adserve_|&popunder=|\/popunder\.|\/popunder_|=popunder&|_popunder\+|\/ad\.html\?|\/ad\/html\/|\/ad_html\/|\.ads9\.|\/ads9\.|\/ads9\/|\-banner\-ads\-|\-banner\-ads\/|\/banner\-ads\-|\/banner\-ads\/|\-adsystem\-|\/adsystem\.|\/adsystem\/|\/ads\-top\.|\/ads\/top\-|\/ads\/top\.|\/ads_top_|\/ads\/index\-|\/ads\/index\.|\/ads\/index\/|\/ads\/index_|\/bannerad\.|\/bannerad\/|_bannerad\.|\.adsense\.|\/adsense\-|\/adsense\/|\/adsense\?|;adsense_|\.ads3\-|\/ads3\.|\/ads3\/|\-dfp\-ads\/|\/dfp\-ads\.|\/dfp\-ads\/|\/a\-ads\.|\/web\-ads\.|\/web\-ads\/|\/web\/ads\/|=web&ads=|&adspace=|\-adspace\.|\-adspace_|\.adspace\.|\/adspace\.|\/adspace\/|\/adspace\?|\/site\-ads\/|\/site\/ads\/|\/site\/ads\?|\-img\/ads\/|\/img\-ads\.|\/img\-ads\/|\/img\.ads\.|\/img\/ads\/|_mobile\/js\/ad\.|\-search\-ads\.|\/search\-ads\?|\/search\/ads\?|\/search\/ads_|\/adb_script\/|\/adstat\.|\.com\/counter\?|\.ads2\-|\/ads2\.|\/ads2\/|\/ads2_|\-adscript\.|\/adscript\.|\/adscript\?|\/adscript_|\/google\/adv\.|\/assets\/sponsored\/|\/admanager\/|\/images\.ads\.|\/images\/ads\-|\/images\/ads\.|\/images\/ads\/|\/images\/ads_|_images\/ads\/|\/media\/ads\/|_media\/ads\/|\/ajax\/track\.php\?|\/plugins\/ad\.|\/adpreview\?|\-google\-ads\-|\-google\-ads\/|\/google\-ads\.|\/google\-ads\/|\/static\/ads\/|_static\/ads\/|&adserver=|\-adserver\-|\-adserver\.|\-adserver\/|\.adserver\.|\/adserver\-|\/adserver\/|\/adserver\?|\/adserver_|\/adshow\-|\/adshow\.|\/adshow\/|\/adshow\?|\/adshow_|=adshow&|\/advlink\.|\-ad\-banner\-|\-ad\-banner\.|\-ad_banner\-|\/ad\-banner\-|\/ad\-banner\.|\/ad\/banner\.|\/ad\/banner\/|\/ad\/banner\?|\/ad\/banner_|\/ad_banner\.|\/ad_banner\/|\/ad_banner_|\/pages\/ads|\?AdUrl=|\-banner\-ad\-|\-banner\-ad\.|\-banner\-ad\/|\/banner\-ad\-|\/banner\-ad\.|\/banner\-ad\/|\/banner\-ad_|\/banner\/ad\.|\/banner\/ad\/|\/banner\/ad_|\/banner_ad\.|_banner\-ad\.|_banner_ad\-|_banner_ad\.|_banner_ad\/|\/product\-ad\/|\/goad$|\/videoad\.|_videoad\.|\.com\/js\/ads\/|\/ads\/popshow\.|&advertiserid=|\/adworks\/|\/tracker\/tracker\.js|\/userad\/|_mainad\.|\/admax\/|_WebAd[^\w.%-]|\/my\-ad\-injector\/|\-ad0\.|\/js\/_analytics\/|\/js\/analytics\.|=advertiser\.|=advertiser\/|\?advertiser=|\/googlead\-|\/googlead\.|_googlead\.|\-images\/ad\-|\/images\-ad\/|\/images\/ad\-|\/images\/ad\/|\/images_ad\/|_images\/ad\.|_images\/ad_|\.net\/adx\.php\?|\.com\/stats\.ashx\?|\/adblocker\/pixel\.|\/adfactory\-|\/adfactory_|\/adplayer\-|\/adplayer\/|\/public\/js\/ad\/|\-adops\.|\/adops\/|\/video\-ads\-management\.|\/ads\/ads\.|\/ads\/ads\/|\/ads\/ads_|\/ga_social_tracking_|\/adwords\/|\.com\/ads\-|\.com\/ads\.|\.com\/ads_|\/com\/ads\/|_ad\.png\?|\/video\-ads\-player\.|\/adlink\?|\/adlink_|\/ad\-minister\-|=adlabs&|\/embed\-log\.js|\/js\/oas\-|\/js\/oas\.|\.com\/im\-ad\/|\.com\/im_ad\/|\/adimg\/|\-advt\.|\/advt\/|\.com\/\?ad=|\.com\/ad\?|\/\?advideo\/|\?advideo_|\/images\/adver\-|\/ad\-manager\/|\/ad_manager\.|\/ad_manager\/|\-advertising\/assets\/|\/adsterra\/|\/ajax\-track\-view\.|\-google\-ad\.|\/google\-ad\-|\/google\-ad\?|\/google\/ad\?|\/google_ad\.|_google_ad\.|\-ad\-pixel\-|\/campaign\/advertiser_|\/adseo\/|\/admedia\/|\/ad\.css\?|\/\?addyn$|\/tracking\/track\.php\?|\/adbroker\.|\/adbroker\/|\/analytics\-v1\.|\-adman\/|\/adman\/|\/adman_|\/socialads\/|_smartads_|\/images\/ad2\/|\/advertisments\/|\/pop_ad\.|_pop_ad\.|_pop_ad\/|\.ads4\-|\/ads4\/|\/amp\-ad\-|\/adblock\-img\.|\-image\-ad\.|\/image\/ad\/|\/adx\/iframe\.|\/adx_iframe_|\/tracker\/track\.php\?|\-adtrack\.|\/adtrack\/|\.net\/ads\-|\.net\/ads\.|\.net\/ads\/|\.net\/ads\?|\.net\/ads_|\/ajax\/optimizely\-|\/track\/track\.php\?|\/flashads\/|\/img\-advert\-|\/adhandler\.|\/wp\-content\/ads\/|\/adimages\.|&adurl=|\/utep_ad\.js|\/adblock_alerter\.|\/adblock\-alerter\/|\/g_track\.php\?|\/_\/ads\/|\?adx=|\/adv\-expand\/|\/adnow\-|\/leaderboard\-advert\.|\.core\.tracking\-min\-|\/sensorsdata\-|\/getad\/|\/getad\?|\/adiframe\.|\/adiframe\/|\/adiframe\?|\/adiframe_|\/chartbeat\.js|_chartbeat\.js|\/admaster\?|\/adverthorisontalfullwidth\.|\.AdmPixelsCacheController\?|\/adaptvexchangevastvideo\.|\/ForumViewTopicContentAD\.|\/postprofilehorizontalad\.|=adreplacementWrapperReg\.|\/adClosefeedbackUpgrade\.|\/adzonecenteradhomepage\.|\/ForumViewTopicBottomAD\.|\/adrolays\.|\/advertisementrotation\.|\/advertisingimageexte\/|\/AdvertisingIsPresent6\?|\/postprofileverticalad\.|\/adblockdetectorwithga\.|\/admanagementadvanced\.|\/advertisementmapping\.|\/initlayeredwelcomead\-|\/advertisementheader\.|\/advertisingcontent\/|\/advertisingwidgets\/|\/thirdpartyframedad\/|\.AdvertismentBottom\.|\/adfrequencycapping\.|\/adgearsegmentation\.|\/advertisementview\/|\/advertising300x250\.|\/advertverticallong\.|\/AdZonePlayerRight2\.|\/ShowInterstitialAd\.|\/addeliverymodule\/|\/adinsertionplugin\.|\/AdPostInjectAsync\.|\/adrendererfactory\.|\/advertguruonline1\.|\/advertisementAPI\/|\/advertisingbutton\.|\/advertisingmanual\.|\/advertisingmodule\.|\/adzonebelowplayer\.|\/adzoneplayerright\.|\/jumpstartunpaidad\.|\?adtechplacementid=|\/adguru\.|\/adasiatagmanager\.|\/adforgame160x600\.|\/adframe728homebh\.|\/adleaderboardtop\.|\/adpositionsizein\-|\/adreplace160x600\.|\/advertise125x125\.|\/advertisement160\.|\/advertiserwidget\.|\/advertisinglinks_|\/advFrameCollapse\.|\/requestmyspacead\.|\/supernorthroomad\.|\/adblockdetection\.|\/adBlockDetector\/|\.advertrecycling\.|\/adbriteincleft2\.|\/adbriteincright\.|\/adchoicesfooter\.|\/adgalleryheader\.|\/adindicatortext\.|\/admatcherclient\.|\/adoverlayplugin\.|\/adreplace728x90\.|\/adtaggingsubsec\.|\/adtagtranslator\.|\/adultadworldpop_|\/advertisements2\.|\/advertisewithus_|\/adWiseShopPlus1\.|\/adwrapperiframe\.|\/contentmobilead\.|\/convertjsontoad\.|\/HompageStickyAd\.|\/mobilephonesad\/|\/sample300x250ad\.|\/tomorrowfocusAd\.|\/adforgame728x90\.|\/adforgame728x90_|\/ero\-advertising\.|\/AdblockMessage\.|\/AdAppSettings\/|\/adinteraction\/|\/adaptvadplayer\.|\/adcalloverride\.|\/adfeedtestview\.|\/adframe120x240\.|\/adframewrapper\.|\/adiframeanchor\.|\/adlantisloader\.|\/adlargefooter2\.|\/adpanelcontent\.|\/adverfisement2\.|\/advertisement1\.|\/advertisement2\.|\/advertisement3\.|\/dynamicvideoad\?|\/premierebtnad\/|\/rotatingtextad\.|\/sample728x90ad\.|\/slideshowintad\?|\/adblockchecker\.|\/adservice\-|\/adservice\/|\/adservice$|\/adblockdetect\.|\/adblockdetect\/|\-advertising11\.|\/adchoicesicon\.|\/adframe728bot\.|\/adframebottom\.|\/adframecommon\.|\/adframemiddle\.|\/adinsertjuicy\.|\/adlargefooter\.|\/adleftsidebar\.|\/admanagement\/|\/adMarketplace\.|\/admentorserve\.|\/adotubeplugin\.|\/adPlaceholder\.|\/advaluewriter\.|\/adverfisement\.|\/advertbuttons_|\/advertising02\.|\/advertisment1\-|\/advertisment4\.|\/bottomsidead\/|\/getdigitalad\/|\/gigyatargetad\.|\/gutterspacead\.|\/leaderboardad\.|\/newrightcolad\.|\/promobuttonad\.|\/rawtubelivead\.|\/restorationad\-|=admodeliframe&|\/adblockkiller\.|\/addpageview\/|\/admonitoring\.|&customSizeAd=|\-printhousead\-|\.advertmarket\.|\/AdBackground\.|\/adcampaigns\/|\/adcomponent\/|\/adcontroller\.|\/adfootcenter\.|\/adframe728b2\.|\/adifyoverlay\.|\/admeldscript\.|\/admentor302\/|\/admentorasp\/|\/adnetwork300\.|\/adnetwork468\.|\/AdNewsclip14\.|\/AdNewsclip15\.|\/adoptionicon\.|\/adrequisitor\-|\/adTagRequest\.|\/adtechHeader\.|\/adtechscript\.|\/adTemplates\/|\/advertisings\.|\/advertsquare\.|\/advertwebapp\.|\/advolatility\.|\/adzonebottom\.|\/adzonelegend\.|\/brightcovead\.|\/contextualad\.|\/custom11x5ad\.|\/horizontalAd\.|\/iframedartad\.|\/indexwaterad\.|\/jsVideoPopAd\.|\/PageBottomAD\.|\/skyscraperad\.|\/writelayerad\.|=dynamicwebad&|\-advertising2\-|\/advertising2\.|\/advtemplate\/|\/advtemplate_|\/adimppixel\/|\-adcompanion\.|\-adtechfront\.|\-advertise01\.|\-rightrailad\-|\.xinhuanetAD\.|\/728x80topad\.|\/adchoices16\.|\/adchoicesv4\.|\/adcollector\.|\/adcontainer\?|\/addelivery\/|\/adfeedback\/|\/adfootright\.|\/AdformVideo_|\/adfoxLoader_|\/adframe728a\.|\/adframe728b\.|\/adfunctions\.|\/adgenerator\.|\/adgraphics\/|\/adhandlers2\.|\/adheadertxt\.|\/adhomepage2\.|\/adiframetop\.|\/admanagers\/|\/admetamatch\?|\/adpictures\/|\/adpolestar\/|\/adPositions\.|\/adproducts\/|\/adrequestvo\.|\/adrollpixel\.|\/adtopcenter\.|\/adtopmidsky\.|\/advcontents\.|\/advertises\/|\/advertlayer\.|\/advertright\.|\/advscripts\/|\/adzoneright\.|\/asyncadload\.|\/crossoverad\-|\/dynamiccsad\?|\/gexternalad\.|\/indexrealad\.|\/instreamad\/|\/internetad\/|\/lifeshowad\/|\/newtopmsgad\.|\/o2contentad\.|\/propellerad\.|\/showflashad\.|\/SpotlightAd\-|\/targetingAd\.|_companionad\.|\.adplacement=|\/adplacement\.|\/adversting\/|\/adversting\?|\/intelliad\.|\.win\/ads\/|\-NewStockAd\-|\.adgearpubs\.|\.rolloverad\.|\/300by250ad\.|\/adbetween\/|\/adbotright\.|\/adboxtable\-|\/adbriteinc\.|\/adchoices2\.|\/adcontents_|\/AdElement\/|\/adexclude\/|\/adexternal\.|\/adfillers\/|\/adflashes\/|\/adFooterBG\.|\/adfootleft\.|\/adformats\/|\/adframe120\.|\/adframe468\.|\/adframetop\.|\/adhandlers\-|\/adhomepage\.|\/adiframe18\.|\/adiframem1\.|\/adiframem2\.|\/adInfoInc\/|\/adlanding\/|\/admanager3\.|\/admanproxy\.|\/admcoreext\.|\/adorika300\.|\/adorika728\.|\/adperfdemo\.|\/AdPreview\/|\/adprovider\.|\/adreplace\/|\/adrequests\.|\/adrevenue\/|\/adrightcol\.|\/adrotator2\.|\/adtextmpu2\.|\/adtopright\.|\/adv180x150\.|\/advertical\.|\/advertmsig\.|\/advertphp\/|\/advertpro\/|\/advertrail\.|\/advertstub\.|\/adviframe\/|\/advlink300\.|\/advrotator\.|\/advtarget\/|\/AdvWindow\/|\/adwidgets\/|\/adWorking\/|\/adwrapper\/|\/adxrotate\/|\/AdZoneAdXp\.|\/adzoneleft\.|\/baselinead\.|\/deliverad\/|\/DynamicAd\/|\/getvideoad\.|\/lifelockad\.|\/lightboxad[^\w.%-]|\/neudesicad\.|\/onplayerad\.|\/photo728ad\.|\/postprocad\.|\/pushdownAd\.|\/PVButtonAd\.|\/renewalad\/|\/rotationad\.|\/sidelinead\.|\/slidetopad\.|\/tripplead\/|\?adlocation=|\?adunitname=|_preorderad\.|\-adrotation\.|\/adgallery2\.|\/adgallery2$|\/adgallery3\.|\/adgallery3$|\/adinjector\.|\/adinjector_|\/adpicture1\.|\/adpicture1$|\/adpicture2\.|\/adpicture2$|\/adrotation\.|\/externalad\.|_externalad\.|\-adfliction\.|\-adfliction\/|\/adfliction\-|\/adbDetect\.|\/adbDetect\/|\/adcontrol\.|\/adcontrol\/|\/adinclude\.|\/adinclude\/|\/adkingpro\-|\/adkingpro\/|\/adoverlay\.|\/adoverlay\/|&adgroupid=|&adpageurl=|\-Ad300x250\.|\-ContentAd\-|\/125x125ad\.|\/300x250ad\.|\/ad125x125\.|\/ad160x600\.|\/ad1x1home\.|\/ad2border\.|\/ad2gather\.|\/ad300home\.|\/ad300x145\.|\/ad600x250\.|\/ad600x330\.|\/ad728home\.|\/adactions\.|\/adasset4\/|\/adbayimg\/|\/adblock26\.|\/adbotleft\.|\/adcentral\.|\/adchannel_|\/adclutter\.|\/adengage0\.|\/adengage1\.|\/adengage2\.|\/adengage3\.|\/adengage4\.|\/adengage5\.|\/adengage6\.|\/adexample\?|\/adfetcher\?|\/adfolder\/|\/adforums\/|\/adheading_|\/adiframe1\.|\/adiframe2\.|\/adiframe7\.|\/adiframe9\.|\/adinator\/|\/AdLanding\.|\/adLink728\.|\/adlock300\.|\/admarket\/|\/admeasure\.|\/admentor\/|\/adNdsoft\/|\/adonly468\.|\/adopspush\-|\/adoptions\.|\/adreclaim\-|\/adrelated\.|\/adruptive\.|\/adtopleft\.|\/adunittop$|\/advengine\.|\/advertize_|\/advertsky\.|\/advertss\/|\/adverttop\.|\/advfiles\/|\/adviewas3\.|\/advloader\.|\/advscript\.|\/advzones\/|\/adwriter2\.|\/adyard300\.|\/adzonetop\.|\/AtomikAd\/|\/contentAd\.|\/contextad\.|\/delayedad\.|\/devicead\/|\/dynamicad\?|\/fetchJsAd\.|\/galleryad\.|\/getTextAD\.|\/GetVASTAd\?|\/invideoad\.|\/MonsterAd\-|\/PageTopAD\.|\/pitattoad\.|\/prerollad\.|\/processad\.|\/ProductAd\.|\/proxxorad\.|\/showJsAd\/|\/siframead\.|\/slideinad\.|\/sliderAd\/|\/spiderad\/|\/testingad\.|\/tmobilead\.|\/unibluead\.|\/vert728ad\.|\/vplayerad\.|\/VXLayerAd\-|\/welcomead\.|=DisplayAd&|\?adcentric=|\?adcontext=|\?adflashid=|\?adversion=|\?advsystem=|\/admonitor\-|\/admonitor\.|\/adrefresh\-|\/adrefresh\.|\/defaultad\.|\/defaultad\?|\/adwizard\.|\/adwizard\/|\/adwizard_|\/adconfig\.|\/adconfig\/|\/addefend\.|\/addefend\/|\/adfactor\/|\/adfactor_|\/adframes\.|\/adframes\/|\/adloader\.|\/adloader\/|\/adwidget\/|\/adwidget_|\/bottomad\.|\/bottomad\/|\/buttonad\/|_buttonad\.|&adclient=|\/adclient\-|\/adclient\.|\/adclient\/|\-Ad300x90\-|\-adcentre\.|\/768x90ad\.|\/ad120x60\.|\/ad1place\.|\/ad290x60_|\/ad468x60\.|\/ad468x80\.|\/AD728cat\.|\/ad728rod\.|\/adarena\/|\/adasset\/|\/adblockl\.|\/adblockr\.|\/adborder\.|\/adbot160\.|\/adbot300\.|\/adbot728\.|\/adbottom\.|\/AdBoxDiv\.|\/adboxes\/|\/adbrite2\.|\/adbucket\.|\/adbucks\/|\/adcast01_|\/adcframe\.|\/adcircle\.|\/adcodes\/|\/adcommon\?|\/adcxtnew_|\/addeals\/|\/adError\/|\/adfooter\.|\/adframe2\.|\/adfront\/|\/adgetter\.|\/adheader\.|\/adhints\/|\/adifyids\.|\/adindex\/|\/adinsert\.|\/aditems\/|\/adlantis\.|\/adleader\.|\/adlinks2\.|\/admicro2\.|\/adModule\.|\/adnotice\.|\/adonline\.|\/adpanel\/|\/adparts\/|\/adplace\/|\/adplace5_|\/adremote\.|\/adroller\.|\/adtagcms\.|\/adtaobao\.|\/adtimage\.|\/adtonomy\.|\/adtop160\.|\/adtop300\.|\/adtop728\.|\/adtopsky\.|\/adtvideo\.|\/advelvet\-|\/advert01\.|\/advert24\.|\/advert31\.|\/advert32\.|\/advert33\.|\/advert34\.|\/advert35\.|\/advert36\.|\/advert37\.|\/adverweb\.|\/adviewed\.|\/adviewer\.|\/adzilla\/|\/anchorad\.|\/attachad\.|\/bigboxad\.|\/btstryad\.|\/couponAd\.|\/customad\.|\/getmyad\/|\/gutterAd\.|\/incmpuad\.|\/injectad\.|\/insertAd\.|\/insideAD\.|\/jamnboad\.|\/jstextad\.|\/leaderad\.|\/localAd\/|\/masterad\.|\/mstextad\?|\/multiad\/|\/noticead\.|\/notifyad\.|\/pencilad\.|\/pledgead\.|\/proto2ad\.|\/salesad\/|\/scrollAd\-|\/spacead\/|\/squaread\.|\/stickyad\.|\/stocksad\.|\/topperad\.|\/tribalad\.|\/VideoAd\/|\/widgetad\.|=ad320x50\-|=adexpert&|\?adformat=|\?adPageCd=|\?adTagUrl=|_adaptvad\.|_StickyAd\.|\-adhelper\.|\/468x60ad\.|\/adhelper\.|\/admarker\.|\/admarker_|\/commonAD\.|\/footerad\.|\/footerad\?|\/headerad\.|_468x60ad\.|_commonAD\.|_headerad\.|\-admarvel\/|\.admarvel\.|\/admarvel\.|\/adometry\-|\/adometry\.|\/adometry\?|\/show\-ad\.|\/show\.ad\?|\/show_ad\.|\/show_ad\?|\/adcycle\.|\/adcycle\/|\/adfiles\.|\/adfiles\/|\/adpeeps\.|\/adpeeps\/|\/adproxy\.|\/adproxy\/|\/advalue\/|\/advalue_|\/adzones\.|\/adzones\/|\/printad\.|\/printad\/|\/servead\.|\/servead\/|\/iframes\/ad\/|\-adimage\-|\/adimage\.|\/adimage\/|\/adimage\?|\/adpixel\.|&largead=|\-adblack\-|\-adhere2\.|\/ad160px\.|\/ad2gate\.|\/ad2push\.|\/ad300f2\.|\/ad300ws\.|\/ad728f2\.|\/ad728ws\.|\/AdAgent_|\/adanim\/|\/adasync\.|\/adboxbk\.|\/adbridg\.|\/adbytes\.|\/adcache\.|\/adctrl\/|\/adedge\/|\/adentry\.|\/adfeeds\.|\/adfever_|\/adflash\.|\/adfshow\?|\/adfuncs\.|\/adgear1\-|\/adgear2\-|\/adhtml\/|\/adlandr\.|\/ADMark\/|\/admatch\-|\/admatik\.|\/adnexus\-|\/adning\/|\/adpagem\.|\/adpatch\.|\/adplan4\.|\/adpoint\.|\/adpool\/|\/adpop32\.|\/adprove_|\/adpush\/|\/adratio\.|\/adroot\/|\/adrotat\.|\/adrotv2\.|\/adtable_|\/adtadd1\.|\/adtagtc\.|\/adtext2\.|\/adtext4\.|\/adtomo\/|\/adtraff\.|\/adutils\.|\/advault\.|\/advdoc\/|\/advert4\.|\/advert5\.|\/advert6\.|\/advert8\.|\/adverth\.|\/advinfo\.|\/adVisit\.|\/advris\/|\/advshow\.|\/adweb33\.|\/adwise\/|\/adzbotm\.|\/adzerk2_|\/adzone1\.|\/adzone4\.|\/bookad\/|\/coread\/|\/flashad\.|\/flytead\.|\/gamead\/|\/hoverad\.|\/imgaad\/|\/jsonad\/|\/LayerAd[^\w.%-]|\/modalad\.|\/nextad\/|\/panelad\.|\/photoad\.|\/promoAd\.|\/rpgetad\.|\/safead\/|\/ServeAd\?|\/smartAd\?|\/transad\.|\/trendad\.|\?adclass=|&advtile=|&smallad=|\-advert3\.|\-sync2ad\-|\.adforge\.|\.admicro\.|\/adcheck\.|\/adcheck\?|\/adfetch\.|\/adfetch\?|\/adforge\.|\/adlift4\.|\/adlift4_|\/adlinks\.|\/adlinks_|\/admicro_|\/adttext\-|\/adttext\.|\/advert3\.|\/smallad\-|\/sync2ad\.|\?advtile=|\-adchain\.|\-advert2\.|\/adchain\-|\/adchain\.|\/advert2\-|\/advert2\.|\/layerad\-|\/layerad\.|_layerad\.|\/adfile\.|\/adfile\/|\/adleft\.|\/adleft\/|\/peelad\.|\/peelad\/|\/sidead\.|\/sidead\/|\/viewad\.|\/viewad\/|\/viewad\?|_sidead\.|&adzone=|\/adzone\.|\/adzone\/|\/adzone_|\?adzone=|\/adinfo\?|\/adpv2\/|\/adtctr\.|\/adtrk\/|&adname=|&AdType=|\.adnwif\.|\.adpIds=|\/ad000\/|\/ad125b\.|\/ad136\/|\/ad160k\.|\/ad2010\.|\/ad2con\.|\/ad300f\.|\/ad300s\.|\/ad300x\.|\/ad728f\.|\/ad728s\.|\/ad728t\.|\/ad728w\.|\/ad728x\.|\/adbar2_|\/adbase\.|\/adbebi_|\/adbl1\/|\/adbl2\/|\/adbl3\/|\/adblob\.|\/adbox1\.|\/adbox2\.|\/adcast_|\/adcla\/|\/adcomp\.|\/adcss\/|\/add728\.|\/adfeed\.|\/adfly\/|\/adicon_|\/adinit\.|\/adjoin\.|\/adjsmp\.|\/adjson\.|\/adkeys\.|\/adlens\-|\/admage\.|\/admega\.|\/adnap\/|\/ADNet\/|\/adnet2\.|\/adnew2\.|\/adpan\/|\/adperf_|\/adping\.|\/adpix\/|\/adplay\.|\/AdPub\/|\/adRoll\.|\/adtabs\.|\/adtago\.|\/adunix\.|\/adutil\.|\/Adv150\.|\/Adv468\.|\/advobj\.|\/advPop\.|\/advts\/|\/advweb\.|\/adweb2\.|\/adx160\.|\/adyard\.|\/adztop\.|\/ajaxAd\?|\/baseAd\.|\/bnrad\/|\/boomad\.|\/cashad\.|\/cubead\.|\/curlad\.|\/cutead\.|\/DemoAd\.|\/dfpad\/|\/divad\/|\/drawad\.|\/ebayad\.|\/flatad\.|\/freead\.|\/fullad\.|\/geoad\/|\/GujAd\/|\/idleAd\.|\/ipadad\.|\/livead\-|\/metaad\.|\/MPUAd\/|\/navad\/|\/newAd\/|\/Nuggad\?|\/postad\.|\/railad\.|\/retrad\.|\/rollad\.|\/rotad\/|\/svnad\/|\/tinyad\.|\/toonad\.|=adMenu&|\?adarea=|\?advurl=|&adflag=|&adlist=|\.adwolf\.|\/adback\.|\/adback\?|\/adflag\.|\/adlist_|\/admain\.|\/admain$|\/adwolf\.|\/adworx\.|\/adworx_|\/footad\-|\/footad\.|\/skinad\.|_skinad\.|\.lazyad\-|\/lazyad\-|\/lazyad\.|\/adpic\.|\/adpic\/|\/adwiz\.|\/adwiz\/|\/flyad\.|\/flyad\/|&adnet=|\/adimp\?|\/adpv\/|&adnum=|\-NewAd\.|\-webAd\-|\/120ad\.|\/300ad\.|\/468ad\.|\/ad11c\.|\/ad125\.|\/ad160\.|\/ad234\.|\/ad250\.|\/ad336\.|\/ad350\.|\/ad468\.|\/adban\.|\/adbet\-|\/adbot_|\/adbtr\.|\/adbug_|\/adCfg\.|\/adcgi\?|\/adfrm\.|\/adGet\.|\/adGpt\.|\/adhug_|\/adixs\.|\/admgr\.|\/adnex\.|\/adpai\.|\/adPos\?|\/adrun\.|\/advdl\.|\/advf1\.|\/advhd\.|\/advph\.|\/advt2\.|\/adxcm_|\/adyea\.|\/affad\?|\/bizad\.|\/buyad\.|\/ciaad\.|\/cnxad\-|\/getAd;|\/ggad\/|\/KfAd\/|\/kitad\.|\/layad\.|\/ledad\.|\/mktad\.|\/mpuad\.|\/natad\.|\/picAd\.|\/pubad\.|\/subAd\.|\/txtad\.|\/ypad\/|\?adloc=|\?PopAd=|_125ad\.|_250ad\.|_FLYAD\.|\.homad\.|\.intad\.|\.intad\/|\/ad728\-|\/ad728\.|\/adrot\.|\/adrot_|\/newad\.|\/newad\?|_homad\.|\/adrum\-|\/adrum\.|\/adrum_|\/ad_pop\.|\/cpx\-advert\/|\/admp\-|\-ad03\.|\.adru\.|\/ad12\.|\/ad15\.|\/ad1r\.|\/ad3i\.|\/ad41_|\/ad4i\.|\/adbn\?|\/adfr\.|\/adjk\.|\/adnl\.|\/adv1\.|\/adv2\.|\/adv5\.|\/adv6\.|\/adv8\.|\/adw1\.|\/adw2\.|\/adw3\.|\/adx2\.|\/adxv\.|\/bbad\.|\/cyad\.|\/o2ad\.|\/pgad\.|\-web\-advert\-|_web\-advert\.|\.net\/ad2\/|\?affiliate=|\/ad8\.|\/nuggad\.|\/nuggad\/|\/pixel\/js\/|\/exoclick$|_doubleclick\.|\-adspot\-|\/adspot\/|\/adspot_|\?adspot_|\/widget\-advert\.|\/widget\-advert\?|\/googleads\-|\/googleads\/|\/googleads_|_googleads_|\/get\-advert\-|\/adblockDetector\.|\/adcash\-|\/adcash$|\/ad_campaigns\/|\/analytics\/track\-|\/analytics\/track\.|\/analytics\/track\/|\/analytics\/track\?|\/analytics\/track$|\/adfox\/|\?adfox_|\/ad2\/index\.|\/ajax\-advert\-|\/ajax\-advert\.|\.biz\/ad2\/|\/adx\-exchange\.|\/adverserve\.|\/bg\-advert\-|\/gujAd\.|\/admeta\.|=admeta&|\-advertising\/vast\/|\/google\-analytics\-|\/google\-analytics\.|\/google\/analytics_|\/google_analytics\.|\/adition\.|\/ad2\/res\/|\/adtest\.|\/adtest\/|\/telegraph\-advertising\/|\/jsad\/|\/Ad\.asmx\/|\/ad_contents\/|\/img2\/ad\/|\/adgallery1\.|\/adgallery1$|\/collections\/ads\-|\/content\/adv\/|\/1\/ads\/|\/stream\-ad\.|\/2\/ads\/|\.com\/ad2\/|\/bottom\-advert\-|\/ad\/swf\/|\/wp_stat\.php\?|\-js\-advertising\-|\-gif\-advert\.|\-advert\-placeholder\.|\/banner\.asp\?|\/cn\-advert\.|\/scripts\/adv\.|\?advert_key=|\/adv_script_|\/script\-adv\-|\.nl\/ad2\/|\?adunitid=|\/ad\/img\/|\/ad_img\.|\/ad_img\/|\/adclix\.|\.com\/log\?event|\.com\/js\/ad\.|\/images\.adv\/|\/images\/adv\-|\/images\/adv\.|\/images\/adv\/|\/images\/adv_|\/ados\?|&advid=|\-analytics\/analytics\.|\/site\-advert\.|\-article\-advert\-|\/article\-advert\-|\/site_under\.|\/advs\/|\/ad2\-728\-|\/layer\-advert\-|\.uk\/track\?|\-advert\-100x100\.|_tracker_min\.|\?ad\.vid=|\?adunit_id=|\/assets\/uts\/|\/ad\/script\/|\/ad_script\.|\/ad_script_|\/scripts\/ad\-|\/scripts\/ad\.|\/scripts\/ad\/|\/scripts\/ad_|\-ad\-scripts\?|\/clickability\-|\/clickability\/|\/clickability\?|_clickability\/|\/ad728x15\.|\/ad728x15_|\/adsatt\.|\/e\-advertising\/|\/ad\.aspx\?|\/adtype\.|\/adtype=|\?adtype=|\/ad24\/|\/affiliate_link\.js|\/ads\/zone\/|\/ads\?zone=|\/eureka\-ads\.|\/images\/adds\/|\/wp\-content\/plugins\/wp\-super\-popup\-pro\/|\-ads\-manager\/|\/ads_manager\.|\.com\/adds\/|\/google\/analytics\.js|\/wp\-js\/analytics\.|\/native\-advertising\/|\/show_ads\.js|\/adv_horiz\.|\.jsp\?adcode=|\/adpicture\.|\/ad\/afc_|\/popad\-|\/popad\.|\.v4\.analytics\.|\/v4\/analytics\.|\/AdvertAssets\/|\-page\-ad\.|\-page\-ad\?|\/page\/ad\/|\/adv3\.|\/wp\-srv\/ad\/|\/adgeo\/|\.php\?id=ads_|\/adtag\.|\/adtag\/|\/adtag\?|\/adtag_|\?adtag=|\/internal\-ad\-|\/ad\-exchange\.|\/ad_entry_|\/wp\-admin\/admin\-ajax\.php\?action=adblockvisitor|\/chitika\-ad\?|\/ads_openx_|\/global\-analytics\.js|\/ad\/files\/|\/ad_files\/|\/scripts\/stats\/|\/files\/ad\-|\/files\/ad\/|_files\/ad\.|\-advertisement\/script\.|\-ad1\.|\/ad1_|\/post\-ad\-|\.in\/ads\.|\.in\/ads\/|\/click\-stat\.js|\/ga_link_tracker_|\/ad\.min\.|\/analytics\.v1\.js|\/corner\-ad\.|\/reklam\-ads2\.|\/marketing\/js\/analytics\/|\/statistics\.php\?data=|_temp\/ad_|\/addyn\/3\.0\/|\/ad_multi_|\/static\/js\/4728ba74bc\.js|\/event\-tracking\.js|\/ad_horiz\.|\/adzonesidead\.|\/ads300\.|\/ads_9_|\/assets\/adv\/|\-ad\.jpg\?|\/advpreload\.|\/stats\/tracker\.js|\/adp\-pro\/|\/set\-cookie\.gif\?|\/statistics\.js\?|\/context_ad\/|\/story_ad\.|\/adclixad\.|\/adreload\.|\/adreload\?|\/wp\-content\/uploads\/useful_banner_manager_banners\/|\-ad\-random\/|\/ad\/random_|\-ad\-left\.|\/ad\-left\.|\/ad_left\.|\/ad_left_|\/ad\-hcm\.|\/adv\.php|\/adifyad\.|\/ad\-blocker\.js|\/adx_flash\.|\/b3\.php\?img=|\/adload\.|\.ws\/ads\/|\/adsx\/|\/wp\-content\/plugins\/anti\-block\/|\/lib\/ad\.js|\/stat\-analytics\/|\-adv\-v1\/|&admeld_|\/admeld\.|\/admeld\/|\/admeld_|=admeld&|\/js\/tracker\.js|\/affiliate_member_banner\/|\-adsmanager\/|\/adsmanager\/|\/widget\/ad\/|_widget_ad\.|\/adv_image\/|\/image\/adv\/|\.fr\/ads\.|\/cpx\-ad\.|\/250x250\-adverts\.|\/ad_campaign\?|\/ad\-third\-party\/|\/all\/ad\/|\/publisher\.ad\.|\.cfm\?advideo%|\/js\/tracking\.js|\.com\/adv\/|\.com\/adv\?|\.com\/adv_|\-gallery_ad\/|\/rcom\-video\-ads\.|\/exports\/tour\/|\/yandex\-metrica\-watch\/|\.com\/log\?type|\/assets\/ad\-|\/assets\/ad\/|\/vs\-track\.js|\-ads\-placement\.|\-simple\-ads\.|\.hr\/ads\.|\/gravity\-beacon\.js|\/analytics\-assets\/|\/adz\/images\/|\/ad\/cross\-|\/assets\/analytics\:|\/images\/adz\-|\/images\/adz\/|\/ads\/xtcore\.|\/adv_top\.|\/pub\/js\/ad\.|\.xyz\/ads\/|\/promo\/ad_|_promo_ad\/|\/ad_mini_|\/images\/bg_ad\/|\/aff_banner\/|\/adblock\.js|\/stat\.php\?|\/ad\/generate\?|\/generate_ad\.|\/adlabs\.js|\/Article\-Ad\-|\/adbrite\-|\/adbrite\.|\/adbrite\/|\/adbrite_|\.net\/affiliate\/|\/ad_rotation\.|&adsize=|\?adsize=|\$csp=worker\-src 'none',domain=estream\.to$flashx\.cc$flashx\.co$flashx\.co$streamango\.com$vidoza\.co$vidoza\.net$vidto\.me$vidto\.se$vidtudu\.com|\/tracking_link_cookie\.|\/ad\-builder\.|\/ad\-iptracer\.|\-ad\-gif\-|\/ad\.gif$|\/ad_gif\/|\/ad_gif_|_ad\.gif$|\/ip\-advertising\/|\?event=advert_|\/stats\-tracking\.js|\/ad_system\/|\/adjs\.|\/adjs\/|\/adjs\?|\/adjs_|\/adv\/mjx\.|\/active\-ad\-|\/AD\-970x90\.|\/assets\/tracking\-|\/ads\/prebid_|\/ajax\-ad\/|\/ajax\/ad\/|\-ad\-300x600\-|\/pagead\.|\/pagead\?|\/adv\.png|\/partner\/transparent_pixel\-|\-load\-advert\.|\/no\-adblock\/|\/wp\-content\/plugins\/deadblocker\/|\/affiliate\-assets\/banner\/|\.text\-link\-ads\.|\/trackings\/addview\/|\.html\?ad=|\.html\?ad_|\/html\/ad\.|\/html\/ad\/|\/webmaster_ads\/|\.tv\/adl\.|\/admin\/banners\/|\/ads\-250\.|\/ads\.json\?|\/utm_cookie\.|\/impressions\/log\?|\-ads\/video\.|\/ads\/video\/|\/ads\/video_|\/adv_flash\.|\/Cookie\?merchant=|\/simple\-tracking\?|\/Ad\/Oas\?|\/create\-lead\.js|\/zalando\-ad\-|\/websie\-ads\-|\/analytics\/eloqua\/|\/_30\/ads\/|\-widget\-advertisement\/|\/ad\/timing\.|\-ads\/oas\/|\/ads\/oas\-|\/ads\/oas\/|\-your\-ad\-here\-|\-amazon\-ads\/|\.widgets\.ad\?|\/stuff\/ad\-|\/doubleclick_head_tag_|\/load\.gif\?|\/log_stats\.php\?|\/pixiedust\-build\.js|\/dynamic\-ad\-|\/dynamic\-ad\/|\/adenc\.|\/adenc_|\/bi_affiliate\.js|\/dfp\/head\/|\-ad\-cube\.|\/ad_medium_|\/ad_links\/|\/ads\-rec$|\/adv\.jsp|\/ads\/exo_|\/ad\/special\.|\/special_ad\.|\.am\/adv\/|\/ads\/rail\-|\-rail\-ads\.|\-rail\-ads\/|\/ad\/window\.php\?|\/pagead\/ads\?|\/akamai_analytics_|\/ad\-callback\.|\/ad\/display\.php|\/tracker_czn\.tsp\?|\/ad_600x160_|\/ad\.cgi\?|\.cgi\?ad=|\/cgi\/ad_|\/affiliate\/ads\/|\/affiliate_show_banner\.|\/wp\-content\/tracker\.|\/ad\-openx\.|\/gen\-ad\-|\?handler=ads&|\/adblock\?id=|\/ad1\/index\.|\/search\-cookie\.aspx\?|\/tracking\.js\?site_id=|\/pickle\-adsystem\/|\/adv\.css\?|\/css\/adv\.|\/u\-ads\.|\/u\/ads\/|\/youtube\-track\-event_|\/client\-event\-logger\.|\/rtt\-log\-data\?|\/affiliate_show_iframe\.|\/div\-ads\.|\/addLinkerEvents\-std\.|\/ads\/navbar\/|\/adx\/js\/|\-advert_August\.|\/add_page_view\?|_ads\-affiliates_|\/json\/ad\/|\/affiliate_base\/banners\/|\/track\.php\?referrer=|\/tracking_add_ons\.|\/ads\-blogs\-|\.adbutler\-|\/adbutler\-|\/adbutler\/|\-load\-ads\.|\/load\-ads$|\/ads\.load\.|\/ads\/load\.|\/ads_load\/|_type=adimg&|\.ad\.json\?|\/lijit\-ad\-|\/ga_no_cookie\.|\/ga_no_cookie_|\/adblock\?action=|\/ad\/ad2\/|\/plugins\/status\.gif\?|\/ads\-common\.|\/ads\/common\/|\/md\.js\?country=|\/admantx\-|\/admantx\.|\/admantx\/|\/affiliates\/contextual\.|\/traffic\-source\-cookie\.|\/traffic\-source\-cookie\/|\/pic\/ads\/|\/ilivid\-ad\-|\/mail_tracking\-cg\.php|\/ifolder\-ads\.|\/wp\-ad\.min\.|\/websie\-ads3\.|\/ade\/baloo\.php|\/im\-ad\/im\-rotator2\.|\/ads\/menu_|\/msn\-exo\-|\/dmn\-advert\.|\/adv_player_|\.net\/flashads|\.com\/adx\/|\.com\/adx_|\/share\/ads\/|\/adv\-div\-|&adserv=|\.adserv\/|\/adserv\.|\/adserv\/|\/adserv_|\/event\?t=view&|\/plugin\/trackEvents\.|\/pagead2\.|\-theme\/ads\/|_theme\/ads\/|\/ads\-03\.|\/ads\/tso|\-ads\/static\-|\/ads\-admin\.|\-ads\-180x|\/ads\-arc\.|\/ads\-cch\-|\/ads\.w3c\.|\/ads\/cbr\.|\/ads\/im2\.|\/ads\?apid|\/ems\/ads\.|\/ia\/ads\/|\/old\/ads\-|\/ome\.ads\.|\/sni\-ads\.|\/tit\-ads\.|\/v7\/ads\/|\/vld\.ads\?|\/ad\/inline\?|\/linktracking\.|\/bci\-ads\.|\/bci\-ads\/|\/tracker\.json\.php\?|\/ads\/125l\.|\/ads\/125r\.|\/ads\/3002\.|\/ads\/468a\.|\/ads\/728b\.|\/ads\/mpu2\?|\/ads\/narf_|\/ads_gnm\/|\/ast\/ads\/|\/cvs\/ads\/|\/dxd\/ads\/|\/esi\/ads\/|\/inv\/ads\/|\/mda\-ads\/|\/sbnr\.ads\?|\/smb\/ads\/|\/ss3\/ads\/|\/tmo\/ads\/|\/tr2\/ads\/|\/ads_door\.|\/nd_affiliate\.|\/idevaffiliate\/banners\/|\/ad_flash\/|\/door\/ads\/|\.refit\.ads\.|\/1912\/ads\/|\/ads\-mopub\?|\/ads\-nodep\.|\/ads\/\?QAPS_|\/ads\/getall|\/ads\/gray\/|\/ads\/like\/|\/ads\/smi24\-|\/bauer\.ads\.|\/img3\/ads\/|\/ispy\/ads\/|\/kento\-ads\-|\/libc\/ads\/|\/subs\-ads\/|\/wire\/ads\/|_html5\/ads\.|\/ads\/daily\.|\/ads\/daily_|\/watchonline_cookies\.|\/daily\/ads\/|\-ads\-530x85\.|\-intern\-ads\/|\/ads\-inside\-|\/ads\-intros\.|\/ads\.compat\.|\/ads\/acctid=|\/ads\/banid\/|\/ads\/bilar\/|\/ads\/box300\.|\/ads\/oscar\/|\/ads\?spaceid|\/ads_codes\/|\/ads_medrec_|\/ads_patron\.|\/ads_sprout_|\/cmlink\/ads\-|\/cssjs\/ads\/|\/digest\/ads\.|\/doors\/ads\/|\/dpics\/ads\/|\/gawker\/ads\.|\/minify\/ads\-|\/skin3\/ads\/|\/webapp\/ads\-|\?ads_params=|\-contrib\-ads\.|\-contrib\-ads\/|\-ads\-Feature\-|\/aderlee_ads\.|\/ads\-reviews\-|\/ads\.jplayer\.|\/ads\/250x120_|\/ads\/300x120_|\/ads\/behicon\.|\/ads\/labels\/|\/ads\/pencil\/|\/ads\/square2\.|\/ads\/square3\.|\/cactus\-ads\/|\/campus\/ads\/|\/develop\/ads_|\/expandy\-ads\.|\/outline\-ads\-|\/uplimg\/ads\/|\/xfiles\/ads\/|\/affiliate\.linker\/|\/ads\-sticker2\.|\/ads\.release\/|\/ads\/cnvideo\/|\/ads\/masthead_|\/ads\/mobiles\/|\/ads\/reskins\/|\/ads\/ringtone_|\/ads\/serveIt\/|\/central\/ads\/|\/cramitin\/ads_|\/gazette\/ads\/|\/hpcwire\/ads\/|\/jetpack\-ads\/|\/jsfiles\/ads\/|\/magazine\/ads\.|\/playerjs\/ads\.|\/taxonomy\-ads\.|\/ads\/webplayer\.|\/ads\/webplayer\?|\/ads\-mobileweb\-|\/ads\-segmentjs\.|\/ads\/leaderbox\.|\/ads\/proposal\/|\/ads\/sidedoor\/|\/ads\/swfobject\.|\/calendar\-ads\/|\/editable\/ads\/|\/releases\/ads\/|\/rule34v2\/ads\/|\/teaseimg\/ads\/|\/affiliate\.1800flowers\.|\/bundles\/Ad\/|\/affiliate\/displayWidget\?|\-floorboard\-ads\/|\/ads\/htmlparser\.|\/ads\/postscribe\.|\/fileadmin\/ads\/|\/moneyball\/ads\/|\/permanent\/ads\/|\/questions\/ads\/|\/standalone\/ads\-|\/teamplayer\-ads\.|\/init_cookie\.php\?|\/affiliate\/small_banner\/|\/libs\/tracker\.js|\/ads\/728x90above_|\/ads\/indexmarket\.|\/excellence\/ads\/|\/userimages\/ads\/|\/flash\/ad\/|\/flash\/ad_|\-ads\/videoblaster\/|\/ads\-restrictions\.|\/ads\/displaytrust\.|\/ads\/scriptinject\.|\/ads\/writecapture\.|\/colorscheme\/ads\/|\/configspace\/ads\/|\/homeoutside\/ads\/|\/incotrading\-ads\/|\/ads\/checkViewport\.|\/ads\/welcomescreen\.|\/photoflipper\/ads\/|\/client\-event\.axd\?|\/ads\/generatedHTML\/|\/customcontrols\/ads\/|\/ads\/contextuallinks\/|\/flowplayer\.ads\.|\/ads\/elementViewability\.|\/adanalytics\.|\/xml\/ad\/|\/local\-ad\.|\/dart_ads\.|\/dart_ads\/|_dart_ads\.|\/global\/ad\/|\/adsmm\.dll\/|\/adv\-scroll\-|\/adv\-scroll\.|\/ad_cache\/|\/ads\/creatives\/|\/banner\.ws\?|\/button_ads\/|\/ads\/head\.|\/ads\/inner_|\/inner\-ads\-|\/inner\-ads\/|\/adv\/topBanners\.|\/skype\-analytics\.|\/adblock\-relief\/|\/adv\/bottomBanners\.|\/adx\/mobile\/|\/04\/ads\-|\/ads\-04\.|\/tracking\/xtcore\.|\.eu\/adv\/|\/flashtag\.txt\?Log=|\/ads\/160\.|\/ads\/160\/|\/ads_160_|\/ads\/branding\/|\/mad\.aspx\?|\/sponsor%20banners\/|\/hosting\/ads\/|\/CookieManager\-bdl\?|\/sitetestclickcount\.enginedocument,script,subdocument|\/storage\/adv\/|\/track_general_stat\.|\/adblocker\.js|\/Logs\/other\?data=|\/carousel_ads\.|\/affiliation_banners\/|\/tracked_ad\.|\/ads\/contextual\.|\/ads\/contextual_|\/tncms\/ads\/|\/adb\.js\?tag=|\/polopoly_fs\/ad\-|\/doubleclick_ads\.|\/doubleclick_ads\/|\?event=performancelogger\:|\/sitefiles\/ads\/|\/ad\.jsp\?|_ad\.jsp\?|\/ad\-record\.|\/pb\-ads\/|\/comscore_engine\.|\/tracker\/emos2_|\.uk\/adv\/|\.org\/adv\/|\/ads\-05\.|\/ads\/imbox\-|;ad_meta=|\/ad\/extra\/|\/ad\/extra_|\/cookie\?affiliate|\/hostkey\-ad\.|\/econa\-site\-search\-ajax\-log\-referrer\.php|\/adv\/desktop\/|\/ads\/motherless\.|\/gen_ads_|\/ads_ifr\.|\.info\/ad_|\/ad\.info\.|\/fc_ads\.|\/adrich\.|\/nb\/ads\/|\/p2\/ads\/|\/cm\/ads\/|\/layout\/ads\/|\/ads\?cookie_|\/public\/adv\/|\/track_yt_vids\.|\/ads\/rect_|\/tracker\/eventBatch\/|\/17\/ads\/|\-SponsorAd\.|\/sponsorad\.|\/ad\-catalogue\-|\/ads\-06\.|\/adonis_event\/|\/cgi\-sys\/count\.cgi\?df=|\/wp\-content\/plugins\/bookingcom\-banner\-creator\/|\/ad\/js\/banner9232\.|\/place\-ads\/|\/adbeacon\.|\?eventtype=request&pid=|\/ad_bannerPool\-|\/bannerfile\/ad_|\/ad_companion\?|\/companion_ad\.|\/ad\/superbanner\.|\.ad\-ocad\.|\/china\-ad\.|\/shared\/ads\.|\/shared\/ads\/|\/affiliate\-tracker\.|\/trackingfilter\.json\?|\/adv\-f\.|\/ads\/popup\.|\/ads\/popup_|\-popup\-ads\-|\/imp\.ads\/|\/pub_images\/|\-ads\-728x|\-ads\/728x|\/includes\/adv\/|_stat\/addEvent\/|\/addons\/ads\/|\/wp\-counter\.php|\/ads\-scroller\-|\/ad\-sovrn\.|\/external\/ad\.|\/external\/ad\/|\/ad_fixedad\.|\/ads\/original\/|\/rcom\-ads\-|\/rcom\-ads\.|\/ads\-07\.|\.lazyload\-ad\-|\.lazyload\-ad\.|\/ad_lazyload\.|\/ads\/frontpage\/|\/library\/adv\/|\-ads\.generated\.|\/tops\.ads\.|\/silver\/ads\/|\/ads\/tile\-|\.biz\/ad\.|\.biz\/ad\/|\/css\/ad\-|\/css\/ad\.|\/assets\/ads3\-|\/analytics\/urlTracker\.|\/track\-compiled\.js|\/plugin\/ad\/|\/js_log_error\.|\/ads\/generator\/|\/javascript\/ads\.|\/javascript\/ads\/|\/adv_server\.|\/ad_selectMainfixedad\.|\/meas\.ad\.pr\.|\/session\-tracker\/tracking\-|\/adv\-placeholder\.|\.com\/ad1\/|\-ad\-plugin\-|\/ad\-plugin\/|\/ads\/community\?|\/event\/rumdata\?|\/ads\.pbs|_blank_ads\.|\/ajaxLogger_tracking_|\/radio\-analytics\.htm|\/ads\-01\.|\/ad_support\.|\/addEvent\?action=|\/ads\/create_|\-analytics\-wi\.|\/ad_config\.|\/addTrackingScripts\.|\/ads_event\.|\/ads\/drive\.|\/ads\/adv\/|\/adv\/ads\/|_ads_v8\.|\/tracking\/setTracker\/|\/compiled\/ads\-|\/adblade\-publisher\-tools\/|\/tracker\-ev\-sdk\.js|\/ad\/select\?|\/watchit_ad\.|\/3pt_ads\.|\/fea_ads\.|\/gtv_ads\.|\/qd_ads\/|\-ad\-large\.|\/ad_large\.|\/Track\.aspx\/|\/geo\-ads_|\/geo\/ads\.|\/service\/adv\/|\/ad\.php\?zone|\/comscore\/pageview_|\/digg_ads\.|\/digg_ads_|\/eco_ads\/|\/flag_ads\.|\/ges_ads\/|\/m0ar_ads\.|\/miva_ads\.|_ads_Home\.|_ads_only&|\/defer_ads\.|\/ifrm_ads\/|=get_preroll_cookie&|\/adv\.asp|\/2011\/ads\/|\-analitycs\/\/metrica\.|\-analitycs\/metrica\.|\/php\-stats\.phpjs\.php\?|\/php\-stats\.recjs\.php\?|\/magic\-ads\/|\/adBlockerTrack_|\/chorus_ads\.|\/torget_ads\.|_ads_single_|\/update_ads\/|\.ng\/ads\/|\/2010\/ads\/|\/ads\/2010\/|\/ad_onclick\.|\/Ad\/premium\/|\/ads\-sa\.|_ads_updater\-|_rightmn_ads\.|_ads\/inhouse\/|\/ads\/dj_|\/graphics\/ad_|\/inhouse_ads\/|\/adv_out\.|\.adrotate\.|\/adrotate\-|\/adrotate\.|\/adrotate\/|\/included_ads\/|_ads_framework\.|\/logo\-ads\.|\/logo\/ads_|\/imagecache_ads\/|\/jsc\/ads\.|\/ad_tpl\.|\/videostreaming_ads\.|\/bftv\/ads\/|\/khan_analystics\.js|_zag_cookie\.|\/ads\/vg\/|\/event\.ng\/|\/player\/ad\/|\/oiopub\-ads\/|_ads_contextualtargeting_|\.swf\?ad=|\/swf\/ad\-|\/adviewtrack\.|\/demo\/ads\/|\/tracker\/trackView\?|\.es\/adv\/|\/vogue_ads\/|\/adv_frame\/|\/mint\/ads\/|\/adtracking\.|\/adtracking\/|\/cookie\/visitor\/|\/ads_check\.|\/ui\/adv\.|\/ui\/adv_|\-AdTracking\.|\/curveball\/ads\/|\/ad\/player_|\/ad\/player$|\.mv\/ads\/|\/pool\.ads\.|\/yahoo_overture\.|\/hw\-ads\.|\/3rd\-party\-stats\/|\/watch\?shu=|\/adserverpub\?|\/log_zon_img\.|\/ads~adsize~|_assets\/metrics\-|\/up\/ads\/|\/adtracker\.|\/adtracker\/|\/adtracker\?|\/adsfuse\-|\/smedia\/ad\/|\/Online\-Adv\-|\/comscore_beacon\.|\/ads01\.|\/adsp\/|\/monetization\/ads\-|\.ashx\?ad=|\/ad\.ashx\?|\/ads\/preloader\/|\/google\-nielsen\-analytics\.|\/ads\/triggers\/|\/tracker\-config\.js|\/viewer\/rad\?|\/newimages\/ads\/|\/modules\/adv\/|_ajax\/btrack\.php\?|\/intermediate\-ad\-|\/vision\/ads\/|\/adgooglefull2\.|\/ads\/rotate\/|\/ads\/rotate_|\.aspx\?ad=|\/styles\/ads\.|\/styles\/ads\/|\/include\/adsdaq|\/ads\/configuration\/|\/adv\/search\.|\/web_cm_event\?|\/ads\/ninemsn\.|\/admvn_pop\.|\/components\/ads\/|\/components\/ads_|\/ads\.bundle\.|\/bundle\/ads\.|\/ads\/real_|\-ads\-master\/|\/qpon_big_ad|\/ram\/ads\/|\/ads\/profile\/|\/fora_player_tracking\.|\/ppd_ads\.|\/ppd_ads_|\/tracking\/digitalData\.|\/analytics\.config\.js|\/tracking\.relead\.|\/ad\/index\.|\/ad\/index\/|\/ad\/index_|\/ad_index_|\/index\-ad\-|\/index\-ad\.|\/index_ad\/|_index_ad\.|\/trackad\.|\/ads_common_library\.|\/ad\-scroll\.|\/thumb\-ads\.|\/ads\-02\.|\/track\-internal\-links\.|\/stats_brand\.js|\/ads_thumb\/|\-ad\/dist\/|\/ima\/ads_|\/ad\-api\-|\/ad\-api\/|\/api\.ad\.|\/api\/ad\/|\/comscore\/streamsense\.|\/big\-ad\-switch\-|\/big\-ad\-switch\/|=big\-ad\-switch_|\/qj\-ads\.|\/assets\/ads\-|\/assets\/ads\.|\/assets\/ads\/|\/assets\/ads_|_assets\/ads\/|\-ads\/assets\/|\/ads\/assets\/|\/ads_assets\/|\/ad_file\/|\/related\-ads\.|\/ads\/freewheel\/|\/scripts\/AdService_|\/adv\-ext\-|\/json\/tracking\/|\-ad\-button\-|\/ad_button\.|\/track\/pix2\.asp\?|\/context_ads\.|\.ads\.loader\-|\/ads_loader\.|\/fm\-ads3\.|\/vb\/ads\/|\/seosite\-tracker\/|\/wp\-content\/mbp\-banner\/|\/templates\/adv_|\/tracking\/tag_commander\.php\?|\/scripts\/tracking\.js|\/AdForm_trackpoint\.|\/AdForm_trackpoint_|\/slideshow\/ads\.|\/ads\/select\/|\/adwords\-conversion\-tracking\.|\/wp\-banners\.js|\/event\/pageview\/|\/event\/pageview\?|\/delfi\-ads\/|\.tz\/ads\/|\/analytics\.bundled\.js|\/adb_iub\.js|\-ads\-tracking\-|\/ads_tracking\.|\/tracking\/ads\.|\-strip\-ads\-|\-ad\-category\-|\?category=ad&|\/frontend\/ads\/|\/stat\/eventManager\/|\/securepubads\.|\/impressions\/(?=([\s\S]*?\/track))\1|\/track\/(?=([\s\S]*?&CheckCookieId=))\2|\/promoredirect\?(?=([\s\S]*?&campaign=))\3(?=([\s\S]*?&zone=))\4|\/images\/a\.gif\?(?=([\s\S]*?=))\5|\$csp=child\-src 'none'; frame\-src (?=([\s\S]*?; worker\-src 'none',domain=adfreetv\.ch$ddmix\.net$extratorrent\.cd$gofile\.io$hq\-porns\.com$intactoffers\.club$myfeed4u\.net$reservedoffers\.club$skyback\.ru$szukajka\.tv$thepiratebay\.cr$thepiratebay\.org$thepiratebay\.red$thevideo\.cc$thevideo\.ch$thevideo\.io$thevideo\.me$thevideo\.us$tvad\.me$vidoza\.net$vidup\.me))\6|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?cpx\.to))\7|\.us\/ad\/(?=([\s\S]*?\?))\8|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?revcontent\.com))\9|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?mc\.yandex\.ru))\10|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?contextual\.media\.net))\11|\/widgets\/adverts\/(?=([\s\S]*?\.))\12|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?viglink\.com))\13|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?static\.getclicky\.com%2Fjs))\14|\/cdn\-cgi\/pe\/bag\?r(?=([\s\S]*?cpalead\.com))\15|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?googleadservices\.com))\16|\$csp=child\-src 'none'; frame\-src 'self' (?=([\s\S]*?; worker\-src 'none',domain=fileone\.tv$theappguruz\.com))\17|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?clkrev\.com))\18|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?nr\-data\.net))\19|\/cdn\-cgi\/pe\/bag\?r(?=([\s\S]*?pubads\.g\.doubleclick\.net))\20|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?google\-analytics\.com%2Fanalytics\.js))\21|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?geoiplookup))\22|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?cdn\.onthe\.io%2Fio\.js))\23|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?content\.ad))\24|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?hs\-analytics\.net))\25|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?adsnative\.com))\26|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?chartbeat\.js))\27|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?log\.outbrain\.com))\28|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.qualitypublishers\.com))\29|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.worldoffersdaily\.com))\30|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?eclkmpbn\.com))\31|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?eclkspsa\.com))\32|\/cdn\-cgi\/pe\/bag2\?r\[\]=(?=([\s\S]*?eth\-pocket\.de))\33|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?bounceexchange\.com))\34|\/\?com=visit(?=([\s\S]*?=record&))\35|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.codeonclick\.com))\36|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?zwaar\.org))\37|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.amazonaws\.com))\38(?=([\s\S]*?secure\.js))\39|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.zergnet\.com))\40|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?revdepo\.com))\41|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?bnserving\.com))\42|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?linksmart\.com))\43|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?puserving\.com))\44|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?intellitxt\.com))\45|\?AffiliateID=(?=([\s\S]*?&campaignsVpIds=))\46|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?newrelic\.com))\47|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?\.speednetwork1\.com))\48|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?scorecardresearch\.com))\49|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.content\-ad\.net))\50|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?ajs\.php))\51|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?juicyads\.com))\52|\$csp=script\-src 'self' 'unsafe\-inline' 'unsafe\-eval' data\: (?=([\s\S]*?\.cloudflare\.com ))\53(?=([\s\S]*?\.google\.com ))\54(?=([\s\S]*?\.addthis\.com ))\55(?=([\s\S]*?\.addthisedge\.com ))\56(?=([\s\S]*?\.facebook\.net ))\57(?=([\s\S]*?\.twitter\.com ))\58(?=([\s\S]*?\.jquery\.com,domain=kinox\.to$kinos\.to$kinox\.sx$kinox\.si$kinox\.io$kinox\.sx$kinox\.am$kinox\.nu$kinox\.sg$kinox\.gratis$kinox\.mobi$kinox\.sh$kinox\.lol$kinox\.wtf$kinox\.fun$kinox\.fyi$kinox\.cloud$kinox\.ai$kinox\.club$kinox\.digital$kinox\.tube$kinox\.direct$kinox\.pub$kinox\.express$kinox\.party$kinox\.space))\59|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?quantserve\.com))\60|\/impressions\/(?=([\s\S]*?\/creative\.png\?))\61|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?az708531\.vo\.msecnd\.net))\62|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?\.google\-analytics\.com))\63|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?adk2\.co))\64|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?mellowads\.com))\65|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?pipsol\.net))\66|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?popcash\.net))\67|\/g00\/(?=([\s\S]*?\/clientprofiler\/adb))\68|\/Redirect\.(?=([\s\S]*?MediaSegmentId=))\69|^javascript\:(?=([\s\S]*?window\.location))\70|\/Log\?(?=([\s\S]*?&adID=))\71|\/affiliates\/(?=([\s\S]*?\/show_banner\.))\72|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?popads\.net))\73|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.adroll\.com))\74|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?yieldbot\.intent\.js))\75|=event&(?=([\s\S]*?_ads%))\76|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?adsrvmedia))\77|\?Id=(?=([\s\S]*?&cookies=))\78(?=([\s\S]*?&Referer_))\79)/i;
var bad_url_parts_flag = 2731 > 0 ? true : false;  // test for non-zero number of rules
    
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
