// PAC (Proxy Auto Configuration) Filter from EasyList rules
// 
// Copyright (C) 2017 by Steven T. Smith <steve dot t dot smith at gmail dot com>, GPL
// https://github.com/essandess/easylist-pac-privoxy/
//
// PAC file created on Fri, 31 May 2019 19:42:45 GMT
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

// 1213 rules:
var bad_da_host_JSON = { "content.ad": null,
"webvisor.ru": null,
"exoclick.com": null,
"nastydollars.com": null,
"adziff.com": null,
"tsyndicate.com": null,
"sharethrough.com": null,
"amazon-adsystem.com": null,
"dianomi.com": null,
"ad.doubleclick.net": null,
"moatads.com": null,
"adsafeprotected.com": null,
"2mdn.net": null,
"doubleclick.net": null,
"go.megabanners.cf": null,
"pagead2.googlesyndication.com": null,
"adchemy-content.com": null,
"ltassrv.com.s3.amazonaws.com": null,
"admitad.com": null,
"serving-sys.com": null,
"g00.msn.com": null,
"coinad.com": null,
"adap.tv": null,
"ip-adress.com": null,
"dashad.io": null,
"optimizely.com": null,
"contentspread.net": null,
"scorecardresearch.com": null,
"adult.xyz": null,
"chartbeat.com": null,
"advertising.com": null,
"click.aliexpress.com": null,
"media.net": null,
"teads.tv": null,
"nuggad.net": null,
"static.parsely.com": null,
"webtrekk.net": null,
"smartadserver.com": null,
"log.pinterest.com": null,
"imasdk.googleapis.com": null,
"adnxs.com": null,
"movad.net": null,
"flashtalking.com": null,
"clicktale.net": null,
"mxcdn.net": null,
"d11a2fzhgzqe7i.cloudfront.net": null,
"rlcdn.com": null,
"stroeerdigitalmedia.de": null,
"adverserve.net": null,
"intelliad.de": null,
"krxd.net": null,
"cm.g.doubleclick.net": null,
"visualwebsiteoptimizer.com": null,
"crwdcntrl.net": null,
"gitcdn.pw": null,
"hotjar.com": null,
"banners.cams.com": null,
"imglnkc.com": null,
"3lift.com": null,
"ace.advertising.com": null,
"revcontent.com": null,
"eclick.baidu.com": null,
"adform.net": null,
"quantserve.com": null,
"xxlargepop.com": null,
"cpx.to": null,
"adition.com": null,
"mediaplex.com": null,
"bluekai.com": null,
"openx.net": null,
"lw2.gamecopyworld.com": null,
"ad.proxy.sh": null,
"adapd.com": null,
"bontent.powvideo.net": null,
"adfox.yandex.ru": null,
"bongacams.com": null,
"adx.kat.ph": null,
"traffic.focuusing.com": null,
"pixel.ad": null,
"adspayformymortgage.win": null,
"adc.stream.moe": null,
"firstclass-download.com": null,
"ad.rambler.ru": null,
"adv.drtuber.com": null,
"ebayobjects.com.au": null,
"trmnsite.com": null,
"yinmyar.xyz": null,
"videoplaza.com": null,
"pdheuryopd.loan": null,
"nkmsite.com": null,
"clickopop1000.com": null,
"megabanners.cf": null,
"uoldid.ru": null,
"money-maker-script.info": null,
"money-maker-default.info": null,
"kdmkauchahynhrs.ru": null,
"abbp1.website": null,
"cashbigo.com": null,
"freecontent.download": null,
"creativecdn.com": null,
"ero-advertising.com": null,
"pos.baidu.com": null,
"ads.yahoo.com": null,
"chartaca.com.s3.amazonaws.com": null,
"abbp1.science": null,
"heapanalytics.com": null,
"ct.pinterest.com": null,
"adlink.net": null,
"adup-tech.com": null,
"getclicky.com": null,
"popads.net": null,
"advertserve.com": null,
"bzclk.baidu.com": null,
"gsp1.baidu.com": null,
"dnn506yrbagrg.cloudfront.net": null,
"log.outbrain.com": null,
"smallseotools.com": null,
"3wr110.xyz": null,
"pixel.facebook.com": null,
"juicyads.com": null,
"adk2.co": null,
"hornymatches.com": null,
"metrics.brightcove.com": null,
"prpops.com": null,
"adonweb.ru": null,
"adcash.com": null,
"htmlhubing.xyz": null,
"videoplaza.tv": null,
"onad.eu": null,
"adtrace.org": null,
"adexc.net": null,
"sexad.net": null,
"admedit.net": null,
"mobsterbird.info": null,
"explainidentifycoding.info": null,
"am10.ru": null,
"xclicks.net": null,
"utarget.ru": null,
"adbooth.com": null,
"adk2.com": null,
"adjuggler.net": null,
"popwin.net": null,
"rapidyl.net": null,
"insta-cash.net": null,
"clicksor.net": null,
"adexchangeprediction.com": null,
"adnetworkperformance.com": null,
"august15download.com": null,
"bentdownload.com": null,
"adultadworld.com": null,
"admngronline.com": null,
"hd-plugin.com": null,
"contentabc.com": null,
"propellerpops.com": null,
"liveadexchanger.com": null,
"ringtonematcher.com": null,
"superadexchange.com": null,
"downloadboutique.com": null,
"adxpansion.com": null,
"alternads.info": null,
"brucelead.com": null,
"venturead.com": null,
"ad-maven.com": null,
"clicksor.com": null,
"ad4game.com": null,
"adplxmd.com": null,
"adrunnr.com": null,
"adxprtz.com": null,
"hpr.outbrain.com": null,
"ad131m.com": null,
"ad2387.com": null,
"adnium.com": null,
"adxite.com": null,
"adbma.com": null,
"adk2x.com": null,
"clickmngr.com": null,
"sharecash.org": null,
"collector.contentexchange.me": null,
"widget.yavli.com": null,
"bullads.net": null,
"xtendmedia.com": null,
"pwrads.net": null,
"whoads.net": null,
"clicktripz.com": null,
"ad6media.fr": null,
"media-servers.net": null,
"888media.net": null,
"c4tracking01.com": null,
"livepromotools.com": null,
"tracking-rce.veeseo.com": null,
"brandreachsys.com": null,
"perfcreatives.com": null,
"kissmetrics.com": null,
"tagcdn.com": null,
"stats.bitgravity.com": null,
"click.scour.com": null,
"statsmobi.com": null,
"ringtonepartner.com": null,
"bettingpartners.com": null,
"clickosmedia.com": null,
"youradexchange.com": null,
"adblade.com": null,
"traffictraffickers.com": null,
"clicksvenue.com": null,
"terraclicks.com": null,
"clicksgear.com": null,
"onclickmax.com": null,
"poponclick.com": null,
"clickfuse.com": null,
"toroadvertisingmedia.com": null,
"mediaseeding.com": null,
"pgmediaserve.com": null,
"waframedia5.com": null,
"wigetmedia.com": null,
"trafficholder.com": null,
"trafficforce.com": null,
"yieldtraffic.com": null,
"traffichaus.com": null,
"trafficshop.com": null,
"fpctraffic2.com": null,
"traktrafficflow.com": null,
"hipersushiads.com": null,
"epicgameads.com": null,
"affbuzzads.com": null,
"megapopads.com": null,
"down1oads.com": null,
"popmyads.com": null,
"filthads.com": null,
"padsdel.com": null,
"1phads.com": null,
"track.xtrasize.nl": null,
"onclickads.net": null,
"pointclicktrack.com": null,
"advmedialtd.com": null,
"adultadmedia.com": null,
"pubads.g.doubleclick.net": null,
"adcdnx.com": null,
"360adstrack.com": null,
"adsrv4k.com": null,
"adsurve.com": null,
"adservme.com": null,
"adsupply.com": null,
"adserverplus.com": null,
"adscpm.net": null,
"adexchangetracker.com": null,
"adglare.org": null,
"adsmarket.com": null,
"adswizz.com": null,
"shareasale.com": null,
"webcams.com": null,
"perfectmarket.com": null,
"reallifecam.com": null,
"freecontent.science": null,
"tubeadvertising.eu": null,
"popshow.info": null,
"freecontent.win": null,
"hm.baidu.com": null,
"urlcash.net": null,
"abctrack.bid": null,
"adfox.ru": null,
"showcase.vpsboard.com": null,
"advertiserurl.com": null,
"addmoredynamiclinkstocontent2convert.bid": null,
"freecontent.trade": null,
"xxxmatch.com": null,
"flcounter.com": null,
"bestforexplmdb.com": null,
"adport.io": null,
"b.photobucket.com": null,
"ad.smartclip.net": null,
"patiskcontentdelivery.info": null,
"trackvoluum.com": null,
"zymerget.win": null,
"plugin.ws": null,
"tostega.ru": null,
"adexchangemachine.com": null,
"adexchangegate.com": null,
"adhealers.com": null,
"admeerkat.com": null,
"adtgs.com": null,
"adm.shinobi.jp": null,
"flagads.net": null,
"aj1574.online": null,
"adright.co": null,
"hodling.science": null,
"popcash.net": null,
"core.queerclick.com": null,
"iwebanalyze.com": null,
"hawkeye-data-production.sciencemag.org.s3-website-us-east-1.amazonaws.com": null,
"adop.cc": null,
"pr-static.empflix.com": null,
"histats.com": null,
"metricfast.com": null,
"trackmytarget.com": null,
"vtracker.net": null,
"topad.mobi": null,
"9content.com": null,
"fastclick.net": null,
"predictivadvertising.com": null,
"bestquickcontentfiles.com": null,
"adglare.net": null,
"showcasead.com": null,
"adhome.biz": null,
"campanja.com": null,
"cookiescript.info": null,
"premium.naturalnews.tv": null,
"synthasite.net": null,
"nextoptim.com": null,
"pc.thevideo.me": null,
"ozon.ru": null,
"intab.xyz": null,
"affiliate.mediatemple.net": null,
"mellowads.com": null,
"adboost.it": null,
"affiliatesmedia.sbobet.com": null,
"tracking.moneyam.com": null,
"vserv.bc.cdn.bitgravity.com": null,
"whatismyip.win": null,
"jshosting.win": null,
"jshosting.science": null,
"indieclick.com": null,
"stats.ibtimes.co.uk": null,
"hilltopads.net": null,
"xs.mochiads.com": null,
"webcounter.ws": null,
"mobtop.ru": null,
"popunderjs.com": null,
"adrotate.se": null,
"codeonclick.com": null,
"googleadservices.com": null,
"lightson.vpsboard.com": null,
"webstats.com": null,
"bid.run": null,
"afimg.liveperson.com": null,
"ams.addflow.ru": null,
"count.livetv.ru": null,
"s11clickmoviedownloadercom.maynemyltf.netdna-cdn.com": null,
"backlogtop.xyz": null,
"wmemsnhgldd.ru": null,
"popunder.ru": null,
"cdnmedia.xyz": null,
"ufpcdn.com": null,
"affiliate.burn-out.tv": null,
"clickredirection.com": null,
"onclicksuper.com": null,
"pulseonclick.com": null,
"topclickguru.com": null,
"onclickmega.com": null,
"tracklab.club": null,
"bonzai.ad": null,
"ingame.ad": null,
"spider.ad": null,
"getalinkandshare.com": null,
"nextlandingads.com": null,
"cookietracker.cloudapp.net": null,
"trackingpro.pro": null,
"cklad.xyz": null,
"mytrack.pro": null,
"vpnaffiliates.hidester.com": null,
"advserver.xyz": null,
"gocp.stroeermediabrands.de": null,
"gstaticadssl.l.google.com": null,
"analytics.us.archive.org": null,
"analytics.163.com": null,
"buythis.ad": null,
"revimedia.com": null,
"affiliate.iamplify.com": null,
"affiliatehub.skybet.com": null,
"cloudset.xyz": null,
"premiumstats.xyz": null,
"fdxstats.xyz": null,
"topbinaryaffiliates.ck-cdn.com": null,
"video.oms.eu": null,
"performancetrack.info": null,
"trafficbroker.com": null,
"trafficstars.com": null,
"ubertracking.info": null,
"33traffic.com": null,
"mobitracker.info": null,
"cache.worldfriends.tv": null,
"affiliate.mercola.com": null,
"adcfrthyo.tk": null,
"dstrack2.info": null,
"trackbar.info": null,
"ad-apac.doubleclick.net": null,
"ad-emea.doubleclick.net": null,
"bannerexchange.com.au": null,
"youroffers.win": null,
"affiliates-cdn.mozilla.org": null,
"admaster.net": null,
"freewheel.mtgx.tv": null,
"analytics.blue": null,
"admo.tv": null,
"adne.tv": null,
"mtrack.nl": null,
"microad.net": null,
"dashbida.com": null,
"u-ad.info": null,
"localytics.com": null,
"adverts.itv.com": null,
"bridgetrack.com": null,
"affiliates.genealogybank.com": null,
"toptracker.ru": null,
"adfrog.info": null,
"adlinx.info": null,
"adalgo.info": null,
"ad.reachlocal.com": null,
"adwalte.info": null,
"adplans.info": null,
"adlerbo.info": null,
"affiliates.mozy.com": null,
"affiliates.vpn.ht": null,
"adm-vids.info": null,
"adproper.info": null,
"advsense.info": null,
"affiliates.mgmmirage.com": null,
"affiliates.goodvibes.com": null,
"affiliates.swappernet.com": null,
"affiliates.treasureisland.com": null,
"affiliates.londonmarketing.com": null,
"advertisingvalue.info": null,
"cdnaz.win": null,
"ininmacerad.pro": null,
"hostingcloud.loan": null,
"ftrack.ru": null,
"pix.speedbit.com": null,
"publicidad.net": null,
"skimresources.com": null,
"zanox-affiliate.de": null,
"free-rewards.com-s.tv": null,
"ewxssoad.bid": null,
"cpaevent.ru": null,
"adofuokjj.bid": null,
"loljuduad.bid": null,
"rqmlurpad.bid": null,
"adbetclickin.pink": null,
"googlerank.info": null,
"adrtgbebgd.bid": null,
"scvonjdwad.bid": null,
"timonnbfad.bid": null,
"totrack.ru": null,
"adnow.com": null,
"hostingcloud.racing": null,
"adnext.org": null,
"ad001.ru": null,
"textad.sexsearch.com": null,
"analytics00.meride.tv": null,
"trackingoffer.info": null,
"advertur.ru": null,
"advombat.ru": null,
"advertone.ru": null,
"chinagrad.ru": null,
"analytic.rocks": null,
"stat.radar.imgsmail.ru": null,
"affiliate.resellerclub.com": null,
"volgograd-info.ru": null,
"partner.googleadservices.com": null,
"sessioncam.com": null,
"analytics.plex.tv": null,
"affiliateprogram.keywordspy.com": null,
"analytics.ifood.tv": null,
"optimize-stats.voxmedia.com": null,
"analytics.ettoredelnegro.pro": null,
"adlure.biz": null,
"statistic.date": null,
"adzjzewsma.cf": null,
"deliberatelyvirtuallyshared.xyz": null,
"link.link.ru": null,
"tracker.azet.sk": null,
"ads.cc": null,
"blogads.com": null,
"hostingcloud.faith": null,
"clarium.global.ssl.fastly.net": null,
"cfcdist.loan": null,
"adlog.com.com": null,
"moevideo.net": null,
"tracker.revip.info": null,
"analytic.pho.fm": null,
"clickpartoffon.xyz": null,
"taeadsnmbbkvpw.bid": null,
"analytics.carambatv.ru": null,
"clicktalecdn.sslcs.cdngc.net": null,
"comscore.com": null,
"adz.zwee.ly": null,
"szzxtanwoptm.bid": null,
"advertise.com": null,
"screencapturewidget.aebn.net": null,
"adsnative.com": null,
"affiliate.com": null,
"blogscash.info": null,
"tracking.vengovision.ru": null,
"videos.oms.eu": null,
"contextads.net": null,
"silverads.net": null,
"ad.gt": null,
"sevenads.net": null,
"bannerbank.ru": null,
"analytics.wildtangent.com": null,
"advnet.xyz": null,
"images.criteo.net": null,
"lead.im": null,
"fnro4yu0.loan": null,
"holexknw.loan": null,
"cpufan.club": null,
"post.rmbn.ru": null,
"pixel.reddit.com": null,
"tracker.tiu.ru": null,
"hostingcloud.bid": null,
"adserved.net": null,
"drowadri.racing": null,
"affiliates.spark.net": null,
"log.ren.tv": null,
"arpelog.info": null,
"advmaker.su": null,
"awstrack.me": null,
"hit-pool.upscore.io": null,
"adsmws.cloudapp.net": null,
"nimiq.watch": null,
"video-ad-stats.googlesyndication.com": null,
"vologda-info.ru": null,
"adfill.me": null,
"engine.gamerati.net": null,
"access-analyze.org": null,
"tracking.hostgator.com": null,
"eiadsdmj.bid": null,
"respond-adserver.cloudapp.net": null,
"adxxx.org": null,
"img.bluehost.com": null,
"analytics.paddle.com": null,
"adnext.fr": null,
"adnet.ru": null,
"ad.spielothek.so": null,
"aimatch.com": null,
"log.worldsoft-cms.info": null,
"adn.ebay.com": null,
"sniperlog.ru": null,
"microad.jp": null,
"track.cooster.ru": null,
"xtracker.pro": null,
"wstats.e-wok.tv": null,
"livestats.la7.tv": null,
"clcknads.pro": null,
"analytics.cmg.net": null,
"analytics.wetpaint.me": null,
"optimost.com": null,
"torads.xyz": null,
"sabin.free.fr": null,
"track.revolvermarketing.ru": null,
"metartmoney.met-art.com": null,
"zoomanalytics.co": null,
"rlogoro.ru": null,
"adten.eu": null,
"analytics.proxer.me": null,
"hotlog.ru": null,
"warlog.ru": null,
"speee-ad.akamaized.net": null,
"ad-vice.biz": null,
"pixel.xmladfeed.com": null,
"addynamics.eu": null,
"tracker2.apollo-mail.net": null,
"adpath.mobi": null,
"leadad.mobi": null,
"oas.luxweb.com": null,
"googleadapis.l.google.com": null,
"webtrack.biz": null,
"adwired.mobi": null,
"adboost.com": null,
"profile.bharatmatrimony.com": null,
"adsjudo.com": null,
"ad2adnetwork.biz": null,
"cloudflare.solutions": null,
"beacon.squixa.net": null,
"hostingcloud.party": null,
"adxxx.me": null,
"beacon.gutefrage.net": null,
"eads.to": null,
"affiliates.lynda.com": null,
"static.kinghost.com": null,
"logxp.ru": null,
"analytics.epi.es": null,
"nicoad.nicovideo.jp": null,
"jqwww.download": null,
"optimalroi.info": null,
"affiliates.minglematch.com": null,
"affiliates.picaboocorp.com": null,
"gandrad.org": null,
"porn-ad.org": null,
"analyticapi.pho.fm": null,
"affiliates.franchisegator.com": null,
"layer-ad.org": null,
"adaction.se": null,
"stats.qmerce.com": null,
"buysellads.net": null,
"visitor-analytics.net": null,
"visit.homepagle.com": null,
"adigniter.org": null,
"popads.media": null,
"jquery-uim.download": null,
"affiliates.myfax.com": null,
"experianmarketingservices.digital": null,
"affiliates.galapartners.co.uk": null,
"monova.site": null,
"quantumws.net": null,
"analytics.gvim.mobi": null,
"adclear.net": null,
"spylog.ru": null,
"pleasedontslaymy.download": null,
"torads.me": null,
"analytics.iraiser.eu": null,
"find-ip-address.org": null,
"cdnfile.xyz": null,
"powerad.ai": null,
"oas.skyscanner.net": null,
"logz.ru": null,
"analytics.archive.org": null,
"adnz.co": null,
"adro.co": null,
"1e0y.xyz": null,
"hdat.xyz": null,
"hhit.xyz": null,
"tracker2kss.eu": null,
"trackerodss.eu": null,
"hivps.xyz": null,
"avero.xyz": null,
"bh8yx.xyz": null,
"retag.xyz": null,
"bnbir.xyz": null,
"analytics.rechtslupe.org": null,
"analytics.truecarbon.org": null,
"cndhit.xyz": null,
"verata.xyz": null,
"acamar.xyz": null,
"alamak.xyz": null,
"pcruxm.xyz": null,
"analytics.codigo.se": null,
"janrain.xyz": null,
"elwraek.xyz": null,
"fyredet.xyz": null,
"patoris.xyz": null,
"albireo.xyz": null,
"alemoney.xyz": null,
"proj2018.xyz": null,
"tidafors.xyz": null,
"checkapi.xyz": null,
"mp3toavi.xyz": null,
"permenor.xyz": null,
"zylstina.xyz": null,
"ficusoid.xyz": null,
"kxqvnfcg.xyz": null,
"trackingoffer.net": null,
"aleinvest.xyz": null,
"quicktask.xyz": null,
"flac2flac.xyz": null,
"tchhelpdmn.xyz": null,
"zapstorage.xyz": null,
"tripedrated.xyz": null,
"alltheladyz.xyz": null,
"mataharirama.xyz": null,
"mobsoftffree.xyz": null,
"adregain.ru": null,
"cruftexcision.xyz": null,
"inspiringsweater.xyz": null,
"advise.co": null,
"honestlypopularvary.xyz": null,
"privilegebedroomlate.xyz": null,
"cnstats.ru": null,
"stabilityappointdaily.xyz": null,
"dfanalytics.dealerfire.com": null,
"performanceanalyser.net": null,
"adcarem.co": null,
"softonic-analytics.net": null,
"hostingcloud.date": null,
"humanclick.com": null,
"analytics-engine.net": null,
"scoutanalytics.net": null,
"fasttracktech.biz": null,
"track2.me": null,
"adbit.biz": null,
"simpleanalytics.io": null,
"trackingapi.cloudapp.net": null,
"gripdownload.co": null,
"pixel.watch": null,
"clkads.com": null,
"affiliate.godaddy.com": null,
"hs-analytics.net": null,
"relead.com": null,
"advatar.to": null,
"manager.koocash.fr": null,
"tracking.vid4u.org": null,
"freetracker.biz": null,
"ad20.net": null,
"adv9.net": null,
"sageanalyst.net": null,
"analyticsip.net": null,
"owlanalytics.io": null,
"trackword.net": null,
"abnad.net": null,
"adf01.net": null,
"adprs.net": null,
"adrsp.net": null,
"bf-ad.net": null,
"dynad.net": null,
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
"i2ad.jp": null,
"advg.jp": null,
"adserve.ph": null,
"webts.adac.de": null,
"ad-back.net": null,
"adgoi-1.net": null,
"adowner.net": null,
"bidhead.net": null,
"adinte.jp": null,
"aid-ad.jp": null,
"adnico.jp": null,
"usenetnl.download": null,
"adc-serv.net": null,
"adbasket.net": null,
"addynamo.net": null,
"admagnet.net": null,
"intextad.net": null,
"onlyalad.net": null,
"tkn.4tube.com": null,
"adadvisor.net": null,
"adglamour.net": null,
"adtegrity.net": null,
"advertpay.net": null,
"augmentad.net": null,
"elasticad.net": null,
"networkad.net": null,
"trackpath.biz": null,
"admatrix.jp": null,
"impact-ad.jp": null,
"individuad.net": null,
"addcontrol.net": null,
"adcastplus.net": null,
"adtransfer.net": null,
"adverticum.net": null,
"content-ad.net": null,
"widgetlead.net": null,
"analytic.piri.net": null,
"ad-balancer.net": null,
"ad-delivery.net": null,
"dashboardad.net": null,
"adimpression.net": null,
"analyzer.qmerce.com": null,
"chartbeat.net": null,
"admaya.in": null,
"admaza.in": null,
"admarketplace.net": null,
"adzmaza.in": null,
"userlog.synapseip.tv": null,
"ihstats.cloudapp.net": null,
"visitor-analytics.io": null,
"analytics.mailmunch.co": null,
"monkeytracker.cz": null,
"advertisingpath.net": null,
"adultcommercial.net": null,
"adultadvertising.net": null,
"adzincome.in": null,
"adchannels.in": null,
"hostingcloud.stream": null,
"metrics.aviasales.ru": null,
"stat.social": null,
"iptrack.biz": null,
"livestats.matrix.it": null,
"count.yandeg.ru": null,
"xfast.host": null,
"event.getblue.io": null,
"analytics.reyrey.net": null,
"analytics.edgekey.net": null,
"analytics.traidnt.net": null,
"etology.com": null,
"analytics.dvidshub.net": null,
"analytics.witglobal.net": null,
"brand.net": null,
"adultsense.org": null,
"analytics.industriemagazin.net": null,
"bb-analytics.jp": null,
"ad.duga.jp": null,
"adtr.io": null,
"analytics.tio.ch": null,
"analytics.arz.at": null,
"yandex-metrica.ru": null,
"adless.io": null,
"adapex.io": null,
"adlive.io": null,
"adnami.io": null,
"advmaker.ru": null,
"adregain.com": null,
"adverti.io": null,
"googleadservicepixel.com": null,
"analytics.solidbau.at": null,
"knowlead.io": null,
"analytics-cms.whitebeard.me": null,
"img.servint.net": null,
"hostingcloud.review": null,
"socialtrack.co": null,
"promotiontrack.mobi": null,
"etracker.de": null,
"socialtrack.net": null,
"analytics.urx.io": null,
"adalliance.io": null,
"adexchange.io": null,
"beacon.mtgx.tv": null,
"admeira.ch": null,
"ad.idgtn.net": null,
"ad.jamba.net": null,
"spinbox.freedom.com": null,
"tags.cdn.circlesix.co": null,
"crazyad.net": null,
"content-offer-app.site": null,
"internalredirect.site": null,
"tracking.thehut.net": null,
"fairad.co": null,
"analytics.suggestv.io": null,
"vihtori-analytics.fi": null,
"tracking.ehavior.net": null,
"tracking.listhub.net": null,
"analoganalytics.com": null,
"ad.pickple.net": null,
"deals.buxr.net": null,
"redirections.site": null,
"traffic-media.co.uk": null,
"tracking.wlscripts.net": null,
"affiliates.thrixxx.com": null,
"adtotal.pl": null,
"visistat.com": null,
"affiliates.bookdepository.com": null,
"track.qcri.org": null,
"counter.gd": null,
"adplusplus.fr": null,
"track.kandle.org": null,
"epnt.ebay.com": null,
"lapi.ebay.com": null,
"ilapi.ebay.com": null,
"tracking.oe24.at": null,
"ad.spreaker.com": null,
"tracking.krone.at": null,
"analytics.carambo.la": null,
"nativeads.com": null,
"tracking.kurier.at": null,
"accede.site": null,
"analytics.yola.net": null,
"adcount.in": null,
"googleme.eu": null,
"promotools.biz": null,
"webads.co.nz": null,
"stat.bilibili.tv": null,
"abbeyblog.me": null,
"infinity-tracking.net": null,
"trackstarsengland.net": null,
"gan.doubleclick.net": null,
"google-rank.org": null,
"trackadvertising.net": null,
"statistics.infowap.info": null,
"cnstats.cdev.eu": null,
"ker.pic2pic.site": null,
"landsraad.cc": null,
"trackdiscovery.net": null,
"trackpromotion.net": null,
"beacon.nuskin.com": null,
"track.atom-data.io": null,
"tracking.customerly.io": null,
"advertica.ae": null,
"tracker.publico.pt": null,
"beacon.tingyun.com": null,
"webstat.no": null,
"stattds.club": null,
"beacon.viewlift.com": null,
"tracetracking.net": null,
"air360tracker.net": null,
"avazutracking.net": null,
"beacon.riskified.com": null,
"tracking.novem.pl": null,
"host-go.info": null,
"realclick.co.kr": null,
"beacon.errorception.com": null,
"beacon.heliumnetwork.com": null,
"beacon.securestudies.com": null,
"counter.webmasters.bpath.com": null,
"trackonomics.net": null,
"analytics.websolute.it": null,
"analytics.digitouch.it": null,
"beacon.wikia-services.com": null,
"googleads.g.doubleclick.net": null,
"stats.teledyski.info": null,
"tracker.mtrax.net": null,
"webtracker.jp": null,
"w4statistics.info": null,
"opentracker.net": null,
"ppctracking.net": null,
"smartracker.net": null,
"trackedlink.net": null,
"roitracking.net": null,
"silverpop.com": null,
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
"ad.kissanime.io": null,
"objects.tremormedia.com": null,
"xvideosharing.site": null,
"sponsoredby.me": null,
"hostip.info": null,
"e-webtrack.net": null,
"maxtracker.net": null,
"trackedweb.net": null,
"trackmyweb.net": null,
"cdn.trafficexchangelist.com": null,
"adgoi.mobi": null,
"track.bluecompany.cl": null,
"etracker.com": null,
"logger.su": null,
"ad.kisscartoon.io": null,
"mstracker.net": null,
"track-web.net": null,
"wisetrack.net": null,
"visits.lt": null,
"smartoffer.site": null,
"letsgoshopping.tk": null,
"analysis.focalprice.com": null,
"adku.co": null,
"trackcmp.net": null,
"tracktrk.net": null,
"zmctrack.net": null,
"analytics-static.ugc.bazaarvoice.com": null,
"k9anf8bc.webcam": null,
"analytics.rambla.be": null,
"cookies.reedbusiness.nl": null,
"analytics.belgacom.be": null,
"hostingcloud.download": null,
"filadmir.site": null,
"gctwh9xc.site": null,
"itempana.site": null,
"jfx61qca.site": null,
"less-css.site": null,
"1wzfew7a.site": null,
"ag2hqdyt.site": null,
"clkdown.info": null,
"affiliate.cx": null,
"estrack.net": null,
"bbtrack.net": null,
"windowne.info": null,
"webstat.net": null,
"video1404.info": null,
"expresided.info": null,
"minexmr.stream": null,
"solutionzip.info": null,
"hodlers.party": null,
"affiligay.net": null,
"downlossinen.info": null,
"hitcount.dk": null,
"playerassets.info": null,
"contentdigital.info": null,
"track.g-bot.net": null,
"arcadebannerexchange.org": null,
"trackword.biz": null,
"goredirect.party": null,
"impressioncontent.info": null,
"seecontentdelivery.info": null,
"webcontentdelivery.info": null,
"zumcontentdelivery.info": null,
"tracker.streamroot.io": null,
"inewcontentdelivery.info": null,
"requiredcollectfilm.info": null,
"buysellads.com": null,
"analytics.matchbin.com": null,
"dom002.site": null,
"analytics.rtbf.be": null,
"coinhive-proxy.party": null,
"tracker.euroweb.net": null,
"tracking.trovaprezzi.it": null,
"onlinereserchstatistics.online": null,
"tracking.conversionlab.it": null,
"utrack.hexun.com": null,
"tracking.conversion-lab.it": null,
"timeslogtn.timesnow.tv": null,
"adip.ly": null,
"track.redirecting2.net": null,
"tjblfqwtdatag.bid": null,
"livestats.fr": null,
"webads.nl": null,
"qom006.site": null,
"gameads.com": null,
"beead.net": null,
"private.camz.": null,
"adorika.net": null,
"adsummos.net": null,
"locotrack.net": null,
"track.derbund.ch": null,
"track.24heures.ch": null,
"brandads.net": null,
"stats.mos.ru": null,
"iperceptions.com": null,
"rentracks.jp": null,
"event.dkb.de": null,
"omoukkkj.stream": null,
"track.cordial.io": null,
"track.codepen.io": null,
"beacon.aimtell.com": null,
"analyticapi.piri.net": null,
"track.mobicast.io": null,
"adku.com": null,
"track.bernerzeitung.ch": null,
"moneroocean.stream": null,
"webassembly.stream": null,
"webstat.se": null,
"intelensafrete.stream": null,
"klapenlyidveln.stream": null,
"stats.lifenews.ru": null,
"ad.cooks.com": null,
"ad.evozi.com": null,
"fan.twitch.tv": null,
"jumplead.com": null,
"speee-ad.jp": null,
"beacon.ehow.com": null,
"pixiedust.buzzfeed.com": null,
"exponderle.pro": null,
"bitx.tv": null,
"laim.tv": null,
"w5statistics.info": null,
"w9statistics.info": null,
"ad.fnnews.com": null,
"htl.bid": null,
"ijncw.tv": null,
"dawin.tv": null,
"affec.tv": null,
"e2yth.tv": null,
"ov8pc.tv": null,
"tracking.to": null,
"carbonads.com": null,
"ad.icasthq.com": null,
"ad.vidaroo.com": null,
"ad.jamster.com": null,
"jstracker.com": null,
"extend.tv": null,
"sponsorselect.com": null,
"stat.ruvr.ru": null,
"adclick.pk": null,
"zaehler.tv": null,
"shoofle.tv": null,
"count.rin.ru": null,
"stat.tvigle.ru": null,
"viedeo2k.tv": null,
"stat.sputnik.ru": null,
"stat.pravmir.ru": null,
"cashtrafic.info": null,
"stat.pladform.ru": null,
"bitfalcon.tv": null,
"pixtrack.in": null,
"liwimgti.bid": null,
"adorika.com": null,
"trackmkxoffers.se": null,
"nativeroll.tv": null,
"depilflash.tv": null,
"directchat.tv": null,
"dm-event.net": null,
"ad.outsidehub.com": null,
"ad.reklamport.com": null,
"ad.lyricswire.com": null,
"g-content.bid": null,
"eimgxlsqj.bid": null,
"filenlgic.bid": null,
"fjmxpixte.bid": null,
"gitcdn.site": null,
"skytvonline.tv": null,
"jumplead.io": null,
"bcoavtimgn.bid": null,
"feacamnliz.bid": null,
"ghizipjlsi.bid": null,
"track2.mycliplister.com": null,
"ad.foxnetworks.com": null,
"axbpixbcucv.bid": null,
"stat.woman-announce.ru": null,
"arqxpopcywrr.bid": null,
"bjkookfanmxx.bid": null,
"nrwofsfancse.bid": null,
"analytics.30m.com": null,
"analytics.r17.com": null,
"log.idnes.cz": null,
"analytics.21cn.com": null,
"pmzktktfanzem.bid": null,
"yxwdppixvzxau.bid": null,
"analytics.favcy.com": null,
"analytics.revee.com": null,
"analytics.brave.com": null,
"analytics.conmio.com": null,
"analytics.kapost.com": null,
"analytics.piksel.com": null,
"analytics.prezly.com": null,
"analytics.aasaam.com": null,
"analytics.jabong.com": null,
"analytics.posttv.com": null,
"analytics.thetab.com": null,
"analytics.zg-api.com": null,
"ad.directmirror.com": null,
"analytics.artirix.com": null,
"analytics.cincopa.com": null,
"analytics.pinpoll.com": null,
"analytics.thenest.com": null,
"analytics.infobae.com": null,
"analytics.audioeye.com": null,
"analytics.hpprintx.com": null,
"analytics.orenshmu.com": null,
"analytics.freespee.com": null,
"analytics.mindjolt.com": null,
"analytics.upworthy.com": null,
"analytics.vendemore.com": null,
"analytics.grupogodo.com": null,
"analytics.sportybet.com": null,
"analytics.teespring.com": null,
"analytics.volvocars.com": null,
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
"nedstat.net": null,
"analytics.midwesternmac.com": null,
"analytics.vanillaforums.com": null,
"analytics.ziftsolutions.com": null,
"analytics.apnewsregistry.com": null,
"analytics.hindustantimes.com": null,
"analytics.convertlanguage.com": null,
"ad.mesomorphosis.com": null,
"ad.theepochtimes.com": null,
"tracking.ustream.tv": null,
"superstat.info": null,
"westatess.info": null,
"analytics.onlyonlinemarketing.com": null,
"analytics.strangeloopnetworks.com": null,
"analytics.disneyinternational.com": null,
"tracking.hrs.de": null,
"log.nordot.jp": null,
"tracking.srv2.de": null,
"adgoi.com": null,
"tracking.linda.de": null,
"tracker.calameo.com": null,
"adzoe.de": null,
"tracking.plinga.de": null,
"tracking.ladies.de": null,
"tracking.sport1.de": null,
"rotaban.ru": null,
"adrise.de": null,
"ad.iloveinterracial.com": null,
"tracking.mvsuite.de": null,
"tracking.netbank.de": null,
"log.mappy.net": null,
"webtracker.apicasystem.com": null,
"adheart.de": null,
"adtraxx.de": null,
"adprovi.de": null,
"paid4ad.de": null,
"track.veedio.it": null,
"adnet.biz": null,
"tracking.emsmobile.de": null,
"eroticmix.blogspot.": null,
"adrank24.de": null,
"tracking.promiflash.de": null,
"an.yandex.ru": null,
"adpionier.de": null,
"wwwstats.info": null,
"my-stats.info": null,
"tracking.hannoversche.de": null,
"adserve.com": null,
"pro-advert.de": null,
"tracking.tchibo.de": null,
"webtracker.educationconnection.com": null,
"abtracker.us": null,
"adtelligence.de": null,
"tracking.goodgamestudios.com": null,
"track.cedsdigital.it": null,
"connect.facebook.com": null,
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
var bad_da_host_exact_flag = 1213 > 0 ? true : false;  // test for non-zero number of rules
    
// 3 rules as an efficient NFA RegExp:
var bad_da_host_RegExp = /^(?:[\w-]+\.)*?(?:images\.(?=([\s\S]*?\.criteo\.net))\1|analytics\-beacon\-(?=([\s\S]*?\.amazonaws\.com))\2|rcm(?=([\s\S]*?\.amazon\.))\3)/i;
var bad_da_host_regex_flag = 3 > 0 ? true : false;  // test for non-zero number of rules

// 295 rules:
var bad_da_hostpath_JSON = { "depositfiles.com/stats.php": null,
"ad.atdmt.com/i/a.js": null,
"ad.atdmt.com/i/a.html": null,
"googletagmanager.com/gtm.js": null,
"imagesnake.com/includes/js/pops.js": null,
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
"viglink.com/images/pixel.gif": null,
"pluso.ru/counter.php": null,
"nyafilmer.com/wp-content/themes/keremiya1/js/script.js": null,
"baidu.com/h.js": null,
"disqus.com/stats.html": null,
"twitvid.com/api/tracking.php": null,
"facebook.com/common/scribe_endpoint.php": null,
"amazonaws.com/g.aspx": null,
"freebunker.com/includes/js/cat.js": null,
"movad.de/c.ount": null,
"plista.com/iframeShowItem.php": null,
"sltrib.com/csp/mediapool/sites/Shared/assets/csp/includes/omniture/SiteCatalystCode_H_17.js": null,
"cloudfront.net/js/reach.js": null,
"myway.com/gca_iframe.html": null,
"cloudfront.net/scripts/js3caf.js": null,
"codecguide.com/stats.js": null,
"wheninmanila.com/wp-content/uploads/2012/12/Marie-France-Buy-1-Take-1-Deal-Discount-WhenInManila.jpg": null,
"eastmoney.com/counter.js": null,
"allmyvideos.net/player/ova-jw.swf": null,
"eageweb.com/stats.php": null,
"elb.amazonaws.com/small.gif": null,
"thefile.me/apu.php": null,
"turboimagehost.com/p1.js": null,
"wired.com/tracker.js": null,
"dpstatic.com/banner.png": null,
"cgmlab.com/tools/geotarget/custombanner.js": null,
"brightcove.com/1pix.gif": null,
"barclaycard.co.uk/cs/static/js/esurveys/esurveys.js": null,
"googletagservices.com/dcm/dcmads.js": null,
"skyrock.net/js/stats_blog.js": null,
"piano-media.com/bucket/novosense.swf": null,
"washingtonpost.com/rw/sites/twpweb/js/init/init.track-header-1.0.0.js": null,
"cafenews.pl/mpl/static/static.js": null,
"ulogin.ru/js/stats.js": null,
"video44.net/gogo/yume-h.swf": null,
"mercola.com/Assets/js/omniture/sitecatalyst/mercola_s_code.js": null,
"websitehome.co.uk/seoheap/cheap-web-hosting.gif": null,
"csmonitor.com/extension/csm_base/design/standard/javascript/adobe/s_code.js": null,
"hitleap.com/assets/banner.png": null,
"ge.com/sites/all/themes/ge_2012/assets/js/bin/s_code.js": null,
"vodo.net/static/images/promotion/utorrent_plus_buy.png": null,
"s-msn.com/s/js/loader/activity/trackloader.min.js": null,
"blogsdna.com/wp-content/themes/blogsdna2011/images/advertisments.png": null,
"revisionworld.co.uk/sites/default/files/imce/Double-MPU2-v2.gif": null,
"charter.com/static/scripts/mock/tracking.js": null,
"zylom.com/pixel.jsp": null,
"playstation.com/pscomauth/groups/public/documents/webasset/community_secured_s_code.js": null,
"tubepornclassic.com/js/111.js": null,
"nitrobahn.com.s3.amazonaws.com/theme/getclickybadge.gif": null,
"cloudfront.net/scripts/cookies.js": null,
"wheninmanila.com/wp-content/uploads/2011/05/Benchmark-Email-Free-Signup.gif": null,
"wheninmanila.com/wp-content/uploads/2014/02/DTC-Hardcore-Quadcore-300x100.gif": null,
"adimgs.t2b.click/assets/js/ttbir.js": null,
"webhostranking.com/images/bluehost-coupon-banner-1.gif": null,
"snazzyspace.com/generators/viewer-counter/counter.php": null,
"nzbking.com/static/nzbdrive_banner.swf": null,
"csmonitor.com/extension/csm_base/design/csm_design/javascript/omniture/s_code.js": null,
"thumblogger.com/thumblog/top_banner_silver.js": null,
"9msn.com.au/share/com/js/fb_google_intercept.js": null,
"watchuseek.com/site/forabar/zixenflashwatch.swf": null,
"gannett-cdn.com/appservices/partner/sourcepoint/sp-mms-client.js": null,
"fncstatic.com/static/all/js/geo.js": null,
"military.com/data/popup/new_education_popunder.htm": null,
"pimpandhost.com/static/html/iframe.html": null,
"sexvideogif.com/msn.js": null,
"yourtv.com.au/share/com/js/fb_google_intercept.js": null,
"adap.tv/redir/client/static/as3adplayer.swf": null,
"phonearena.com/_track.php": null,
"wheninmanila.com/wp-content/uploads/2014/04/zion-wifi-social-hotspot-system.png": null,
"ford.com/ngtemplates/ngassets/com/forddirect/ng/newMetrics.js": null,
"forms.aweber.com/form/styled_popovers_and_lightboxes.js": null,
"baymirror.com/static/img/bar.gif": null,
"aeroplan.com/static/js/omniture/s_code_prod.js": null,
"dl-protect.com/pop.js": null,
"hotdeals360.com/static/js/kpwidgetweb.js": null,
"aircanada.com/shared/common/sitecatalyst/s_code.js": null,
"static.tumblr.com/dhqhfum/WgAn39721/cfh_header_banner_v2.jpg": null,
"jeuxvideo.com/contenu/medias/video/countv.php": null,
"dexerto.com/app/uploads/2016/11/Gfuel-LemoNade.jpg": null,
"liveonlinetv247.com/images/muvixx-150x50-watch-now-in-hd-play-btn.gif": null,
"ford.com/ngtemplates/ngassets/ford/general/scripts/js/galleryMetrics.js": null,
"expressen.se/static/scripts/s_code.js": null,
"audiusa.com/us/brand/en.usertracking_javascript.js": null,
"ultimatewindowssecurity.com/securitylog/encyclopedia/images/allpartners.swf": null,
"naptol.com/usr/local/csp/staticContent/js/ga.js": null,
"attorrents.com/static/images/download3.png": null,
"libertyblitzkrieg.com/wp-content/uploads/2012/09/cc200x300.gif": null,
"btkitty.org/static/images/880X60.gif": null,
"saabsunited.com/wp-content/uploads/REALCAR-SAABSUNITED-5SEC.gif": null,
"skyrock.net/img/pix.gif": null,
"streams.tv/js/bn5.js": null,
"tpb.piraten.lu/static/img/bar.gif": null,
"cdnplanet.com/static/rum/rum.js": null,
"amazonaws.com/pmb-musics/download_itunes.png": null,
"soe.com/js/web-platform/web-data-tracker.js": null,
"emergencymedicalparamedic.com/wp-content/uploads/2011/12/anatomy.gif": null,
"btkitty.com/static/images/880X60.gif": null,
"privacytool.org/AnonymityChecker/js/fontdetect.js": null,
"sexier.com/services/adsredirect.ashx": null,
"ultimatewindowssecurity.com/images/banner80x490_WSUS_FreeTool.jpg": null,
"better-explorer.com/wp-content/uploads/2013/07/hf.5.png": null,
"vidyoda.com/fambaa/chnls/ADSgmts.ashx": null,
"better-explorer.com/wp-content/uploads/2012/09/credits.png": null,
"cloudfront.net/track.html": null,
"staticbucket.com/boost//Scripts/libs/flickity.js": null,
"watchuseek.com/media/longines_legenddiver.gif": null,
"ebizmbainc.netdna-cdn.com/images/tab_sponsors.gif": null,
"downloadsmais.com/imagens/download-direto.gif": null,
"lightboxcdn.com/static/identity.html": null,
"whatreallyhappened.com/webpageimages/banners/uwslogosm.jpg": null,
"johnbridge.com/vbulletin/images/tyw/cdlogo-john-bridge.jpg": null,
"paypal.com/acquisition-app/static/js/s_code.js": null,
"shopping.com/sc/pac/sdc_widget_v2.0_proxy.js": null,
"microsoft.com/getsilverlight/scripts/silverlight/SilverlightAtlas-MSCOM-Tracking.js": null,
"livetradingnews.com/wp-content/uploads/vamp_cigarettes.png": null,
"lexus.com/lexus-share/js/campaign_tracking.js": null,
"crabcut.net/popup.js": null,
"nih.gov/share/scripts/survey.js": null,
"static.pes-serbia.com/prijatelji/zero.png": null,
"shopify.com/track.js": null,
"themag.co.uk/assets/BV200x90TOPBANNER.png": null,
"razor.tv/site/servlet/tracker.jsp": null,
"careerwebsite.com/distrib_pages/jobs.cfm": null,
"watchseries.eu/images/download.png": null,
"desiretoinspire.net/storage/layout/royalcountessad.gif": null,
"whitedolly.com/wcf/images/redbar/logo_neu.gif": null,
"quintcareers.4jobs.com/Common/JavaScript/functions.tracking.js": null,
"sexilation.com/wp-content/uploads/2013/01/Untitled-1.jpg": null,
"investegate.co.uk/Weblogs/IGLog.aspx": null,
"fileplanet.com/fileblog/sub-no-ad.shtml": null,
"xbox-scene.com/crave/logo_on_white_s160.jpg": null,
"domainapps.com/assets/img/domain-apps.gif": null,
"addtoany.com/menu/transparent.gif": null,
"androidfilehost.com/libs/otf/stats.otf.php": null,
"ibtimes.com/player/stats.swf": null,
"ino.com/img/sites/mkt/click.gif": null,
"meanjin.com.au/static/images/sponsors.jpg": null,
"taringa.net/ajax/track-visit.php": null,
"webmd.com/dtmcms/live/webmd/PageBuilder_Assets/JS/oas35.js": null,
"youwatch.org/vod-str.html": null,
"technewsdaily.com/crime-stats/local_crime_stats.php": null,
"myanimelist.net/static/logging.html": null,
"zipcode.org/site_images/flash/zip_v.swf": null,
"flashi.tv/histats.php": null,
"mnginteractive.com/live/js/omniture/SiteCatalystCode_H_22_1_NC.js": null,
"images.military.com/pixel.gif": null,
"pimpandhost.com/images/pah-download.gif": null,
"uploadshub.com/downloadfiles/download-button-blue.gif": null,
"healthcarejobsite.com/Common/JavaScript/functions.tracking.js": null,
"jillianmichaels.com/images/publicsite/advertisingslug.gif": null,
"saabsunited.com/wp-content/uploads/rbm21.jpg": null,
"saabsunited.com/wp-content/uploads/USACANADA.jpg": null,
"imageteam.org/upload/big/2014/06/22/53a7181b378cb.png": null,
"pcgamesn.com/sites/default/files/SE4L.JPG": null,
"cardstore.com/affiliate.jsp": null,
"ewrc-results.com/images/horni_ewrc_result_banner3.jpg": null,
"ibrod.tv/ib.php": null,
"worldnow.com/global/tools/video/Namespace_VideoReporting_DW.js": null,
"arstechnica.com/dragons/breath.gif": null,
"shareit.com/affiliate.html": null,
"kuiken.co/static/w.js": null,
"watchuseek.com/media/clerc-final.jpg": null,
"cruisesalefinder.co.nz/affiliates.html": null,
"videobull.to/wp-content/themes/videozoom/images/gotowatchnow.png": null,
"webtutoriaux.com/services/compteur-visiteurs/index.php": null,
"friday-ad.co.uk/endeca/afccontainer.aspx": null,
"samsung.com/ph/nextisnow/files/javascript.js": null,
"jappy.tv/i/wrbng/abb.png": null,
"sofascore.com/geoip.js": null,
"messianictimes.com/images/Jews%20for%20Jesus%20Banner.png": null,
"statig.com.br/pub/setCookie.js": null,
"washingtonpost.com/wp-srv/javascript/piggy-back-on-ads.js": null,
"pcgamesn.com/sites/default/files/Se4S.jpg": null,
"greyorgray.com/images/Fast%20Business%20Loans%20Ad.jpg": null,
"syndication.visualthesaurus.com/std/vtad.js": null,
"imgdino.com/gsmpop.js": null,
"videobull.to/wp-content/themes/videozoom/images/stream-hd-button.gif": null,
"picturevip.com/imagehost/top_banners.html": null,
"watchuseek.com/media/wus-image.jpg": null,
"youwatch.org/driba.html": null,
"youwatch.org/9elawi.html": null,
"youwatch.org/iframe1.html": null,
"cams.com/p/cams/cpcs/streaminfo.cgi": null,
"nih.gov/medlineplus/images/mplus_en_survey.js": null,
"rednationonline.ca/Portals/0/derbystar_leaderboard.jpg": null,
"better-explorer.com/wp-content/uploads/2013/10/PoweredByNDepend.png": null,
"wearetennis.com/img/common/bnp-logo.png": null,
"videoszoofiliahd.com/wp-content/themes/vz/js/p.js": null,
"desiretoinspire.net/storage/layout/modmaxbanner.gif": null,
"as.jivox.com/jivox/serverapis/getcampaignbysite.php": null,
"letour.fr/img/v6/sprite_partners_2x.png": null,
"mywot.net/files/wotcert/vipre.png": null,
"cbc.ca/video/bigbox.html": null,
"gold-prices.biz/gold_trading_leader.gif": null,
"kau.li/yad.js": null,
"js.static.m1905.cn/pingd.js": null,
"nbcudigitaladops.com/hosted/housepix.gif": null,
"hostingtoolbox.com/bin/Count.cgi": null,
"bongacash.com/tools/promo.php": null,
"qbn.com/media/static/js/ga.js": null,
"watchop.com/player/watchonepiece-gao-gamebox.swf": null,
"tubeplus.me/resources/js/codec.js": null,
"scientopia.org/public_html/clr_lympholyte_banner.gif": null,
"johnbridge.com/vbulletin/images/tyw/wedi-shower-systems-solutions.png": null,
"forward.com/workspace/assets/newimages/amazon.png": null,
"englishgrammar.org/images/30off-coupon.png": null,
"kleisauke.nl/static/img/bar.gif": null,
"publicdomaintorrents.info/srsbanner.gif": null,
"prospects.ac.uk/assets/js/prospectsWebTrends.js": null,
"russellgrant.com/hostedsearch/panelcounter.aspx": null,
"washtimes.com/static/images/SelectAutoWeather_v2.gif": null,
"file.org/fo/scripts/download_helpopt.js": null,
"unblockedpiratebay.com/static/img/bar.gif": null,
"dj.rasset.ie/dotie/js/rte.ads.js": null,
"klm.com/travel/generic/static/js/measure_async.js": null,
"staticice.com.au/cgi-bin/stats.cgi": null,
"fileom.com/img/downloadnow.png": null,
"rtlradio.lu/stats.php": null,
"serial.sw.cracks.me.uk/img/logo.gif": null,
"watchseries.eu/js/csspopup.js": null,
"devilgirls.co/images/devil.gif": null,
"makeagif.com/parts/fiframe.php": null,
"releaselog.net/uploads2/656d7eca2b5dd8f0fbd4196e4d0a2b40.jpg": null,
"kitguru.net/wp-content/wrap.jpg": null,
"swatchseries.to/bootstrap.min.js": null,
"timesnow.tv/googlehome.cms": null,
"euronews.com/media/farnborough/farnborough_wp.jpg": null,
"playomat.de/sfye_noscript.php": null,
"lazygirls.info/click.php": null,
"24hourfitness.com/includes/script/siteTracking.js": null,
"cash9.org/assets/img/banner2.gif": null,
"uramov.info/wav/wavideo.html": null,
"hwbot.org/banner.img": null,
"live-medias.net/button.php": null,
"merchantcircle.com/static/track.js": null,
"celebstoner.com/assets/images/img/top/420VapeJuice960x90V3.gif": null,
"odnaknopka.ru/stat.js": null,
"digitizor.com/wp-content/digimages/xsoftspyse.png": null,
"publicdomaintorrents.info/grabs/hdsale.png": null,
"jivox.com/jivox/serverapis/getcampaignbyid.php": null,
"fujifilm.com/js/shared/analyzer.js": null,
"fantasti.cc/ajax/gw.php": null,
"ablacrack.com/popup-pvd.js": null,
"vbs.tv/tracker.html": null,
"lijit.com/adif_px.php": null,
"script.idgentertainment.de/gt.js": null,
"go4up.com/assets/img/download-button.png": null,
"judgeporn.com/video_pop.php": null,
"momtastic.com/libraries/pebblebed/js/pb.track.js": null,
"amazonaws.com/accio-lib/accip_script.js": null,
"thevideo.me/mba/cds.js": null,
"netdna-ssl.com/wp-content/uploads/2017/01/tla17janE.gif": null,
"netdna-ssl.com/wp-content/uploads/2017/01/tla17sepB.gif": null,
"alladultnetwork.tv/main/videoadroll.xml": null,
"checker.openwebtorrent.com/digital-ocean.jpg": null,
"filestream.me/requirements/images/cialis_generic.gif": null,
"mail.yahoo.com/mc/md.php": null,
"letswatchsomething.com/images/filestreet_banner.jpg": null,
"atom-data.io/session/latest/track.html": null,
"bc.vc/images/megaload.gif": null,
"oscars.org/scripts/wt_include1.js": null,
"oscars.org/scripts/wt_include2.js": null,
"interracialbangblog.info/banner.jpg": null,
"twinsporn.net/images/free-penis-pills.png": null,
"xxxselected.com/cdn_files/dist/js/blockPlaces.js": null,
"d-h.st/assets/img/download1.png": null,
"homepage-baukasten.de/cookie.php": null,
"24video.net/din_new6.php": null,
"playgirl.com/pg/media/prolong_ad.png": null,
"scriptlance.com/cgi-bin/freelancers/ref_click.cgi": null,
"watchfree.to/topright.php": null,
"mercuryinsurance.com/static/js/s_code.js": null,
"binsearch.info/iframe.php": null,
"cclickvidservgs.com/mattel/cclick.js": null,
"bc.vc/adbcvc.html": null,
"google-analytics.com/siteopt.js": null,
"paper.li/javascripts/analytics.js": null,
"virginholidays.co.uk/_assets/js/dc_storm/track.js": null,
"rightmove.co.uk/ps/images/logging/timer.gif": null,
"filestream.me/requirements/images/ed.gif": null };
var bad_da_hostpath_exact_flag = 295 > 0 ? true : false;  // test for non-zero number of rules
    
// 939 rules as an efficient NFA RegExp:
var bad_da_hostpath_RegExp = /^(?:[\w-]+\.)*?(?:doubleclick\.net\/adx\/|doubleclick\.net\/adj\/|piano\-media\.com\/uid\/|jobthread\.com\/t\/|pornfanplace\.com\/js\/pops\.|porntube\.com\/adb\/|quantserve\.com\/pixel\/|doubleclick\.net\/pixel|addthiscdn\.com\/live\/|baidu\.com\/pixel|doubleclick\.net\/ad\/|netdna\-ssl\.com\/tracker\/|adf\.ly\/_|imageshack\.us\/ads\/|firedrive\.com\/tools\/|freakshare\.com\/banner\/|adform\.net\/banners\/|amazonaws\.com\/analytics\.|adultfriendfinder\.com\/banners\/|facebook\.com\/tr|baidu\.com\/ecom|widgetserver\.com\/metrics\/|veeseo\.com\/tracking\/|google\-analytics\.com\/plugins\/|channel4\.com\/ad\/|chaturbate\.com\/affiliates\/|redtube\.com\/stats\/|sextronix\.com\/images\/|barnebys\.com\/widgets\/|domaintools\.com\/partners\/|google\.com\/analytics\/|view\.atdmt\.com\/partner\/|adultfriendfinder\.com\/javascript\/|yahoo\.com\/track\/|cloudfront\.net\/track|yahoo\.com\/beacon\/|4tube\.com\/iframe\/|visiblemeasures\.com\/log|cursecdn\.com\/banner\/|pop6\.com\/banners\/|google\-analytics\.com\/gtm\/js|pcwdld\.com\/wp\-content\/plugins\/wbounce\/|propelplus\.com\/track\/|wupload\.com\/referral\/|dditscdn\.com\/log\/|adultfriendfinder\.com\/go\/|mediaplex\.com\/ad\/js\/|wtprn\.com\/sponsors\/|xvideos\-free\.com\/d\/|imagetwist\.com\/banner\/|github\.com\/_stats|wired\.com\/event|photobucket\.com\/track\/|slashgear\.com\/stats\/|hothardware\.com\/stats\/|sex\.com\/popunder\/|healthtrader\.com\/banner\-|siberiantimes\.com\/counter\/|voyeurhit\.com\/contents\/content_sources\/|pornoid\.com\/contents\/content_sources\/|lovefilm\.com\/partners\/|xxxhdd\.com\/contents\/content_sources\/|xxvideo\.us\/ad728x15|broadbandgenie\.co\.uk\/widget|topbucks\.com\/popunder\/|powvideo\.net\/ban\/|video\-cdn\.abcnews\.com\/ad_|livedoor\.com\/counter\/|pornalized\.com\/contents\/content_sources\/|primevideo\.com\/uedata\/|vodpod\.com\/stats\/|baidu\.com\/billboard\/pushlog\/|soufun\.com\/stats\/|zawya\.com\/ads\/|msn\.com\/tracker\/|shareasale\.com\/image\/|cnn\.com\/ad\-|soundcloud\.com\/event|rapidgator\.net\/images\/pics\/|fwmrm\.net\/ad\/|appspot\.com\/stats|static\.criteo\.net\/js\/duplo[^\w.%-]|hstpnetwork\.com\/ads\/|fapality\.com\/contents\/content_sources\/|sawlive\.tv\/ad|sourceforge\.net\/log\/|videowood\.tv\/ads|conduit\.com\/\/banners\/|adroll\.com\/pixel\/|ad\.admitad\.com\/banner\/|googlesyndication\.com\/sodar\/|googlesyndication\.com\/safeframe\/|secureupload\.eu\/banners\/|hosting24\.com\/images\/banners\/|sparklit\.com\/counter\/|red\-tube\.com\/popunder\/|daylogs\.com\/counter\/|phncdn\.com\/iframe|gamestar\.de\/_misc\/tracking\/|videoplaza\.tv\/proxy\/tracker[^\w.%-]|filecrypt\.cc\/p\.|chameleon\.ad\/banner\/|nytimes\.com\/ads\/|twitter\.com\/i\/jot|spacash\.com\/popup\/|pan\.baidu\.com\/api\/analytics|liutilities\.com\/partners\/|addthis\.com\/live\/|youtube\.com\/pagead\/|vidzi\.tv\/mp4|girlfriendvideos\.com\/ad|doubleclick\.net\/pfadx\/video\.marketwatch\.com\/|keepvid\.com\/ads\/|ad\.atdmt\.com\/s\/|static\.criteo\.net\/images[^\w.%-]|theporncore\.com\/contents\/content_sources\/|citygridmedia\.com\/ads\/|chaturbate\.com\/creative\/|worldfree4u\.top\/banners\/|ad\.doubleclick\.net\/ddm\/trackclk\/|anysex\.com\/assets\/|twitter\.com\/metrics|dailymotion\.com\/track\-|dailymotion\.com\/track\/|shareaholic\.com\/analytics_|kqzyfj\.com\/image\-|jdoqocy\.com\/image\-|tkqlhce\.com\/image\-|cfake\.com\/images\/a\/|hqq\.tv\/js\/betterj\/|ad\.atdmt\.com\/e\/|virool\.com\/widgets\/|trrsf\.com\/metrics\/|advfn\.com\/tf_|quora\.com\/_\/ad\/|ad\.admitad\.com\/fbanner\/|aliexpress\.com\/js\/beacon_|mygaming\.co\.za\/news\/wp\-content\/wallpapers\/|ad\.atdmt\.com\/i\/img\/|reevoo\.com\/track\/|youtube\-nocookie\.com\/gen_204|tube18\.sex\/tube18\.|howtogermany\.com\/banner\/|mochiads\.com\/srv\/|xhamster\.com\/ads\/|pornmaturetube\.com\/content\/|doubleclick\.net\/pfadx\/ugo\.gv\.1up\/|videoplaza\.com\/proxy\/distributor\/|youtube\.com\/ptracking|static\.criteo\.com\/flash[^\w.%-]|livefyre\.com\/tracking\/|static\.criteo\.com\/images[^\w.%-]|carbiz\.in\/affiliates\-and\-partners\/|ad\.mo\.doubleclick\.net\/dartproxy\/|doubleclick\.net\/pfadx\/mc\.channelnewsasia\.com[^\w.%-]|rt\.com\/static\/img\/banners\/|amazon\.com\/clog\/|andyhoppe\.com\/count\/|video\.mediaset\.it\/polymediashowanalytics\/|ncrypt\.in\/images\/a\/|mtvnservices\.com\/metrics\/|fulltiltpoker\.com\/affiliates\/|autotrader\.co\.za\/partners\/|sun\.com\/share\/metrics\/|videowood\.tv\/pop2|static\.game\-state\.com\/images\/main\/alert\/replacement\/|doubleclick\.net\/pfadx\/intl\.sps\.com\/|doubleclick\.net\/pfadx\/nbcu\.nhl\.|doubleclick\.net\/pfadx\/nbcu\.nhl\/|doubleclick\.net\/pfadx\/blp\.video\/midroll|questionmarket\.com\/static\/|thrixxx\.com\/affiliates\/|allmyvideos\.net\/js\/ad_|doubleclick\.net\/activity|hostgator\.com\/~affiliat\/cgi\-bin\/affiliates\/|doubleclick\.net\/pfadx\/tmz\.video\.wb\.dart\/|doubleclick\.net\/pfadx\/bzj\.bizjournals\/|doubleclick\.net\/pfadx\/ndm\.tcm\/|doubleclick\.net\/adx\/wn\.nat\.|supplyframe\.com\/partner\/|doubleclick\.net\/pfadx\/gn\.movieweb\.com\/|doubleclick\.net\/pfadx\/miniclip\.midvideo\/|doubleclick\.net\/pfadx\/miniclip\.prevideo\/|bristolairport\.co\.uk\/~\/media\/images\/brs\/blocks\/internal\-promo\-block\-300x250\/|femalefirst\.co\.uk\/widgets\/|phncdn\.com\/images\/banners\/|banners\.friday\-ad\.co\.uk\/hpbanneruploads\/|amazonaws\.com\/bo\-assets\/production\/banner_attachments\/|any\.gs\/visitScript\/|upsellit\.com\/custom\/|akamai\.net\/chartbeat\.|wishlistproducts\.com\/affiliatetools\/|addthis\.com\/at\/|softpedia\-static\.com\/images\/aff\/|amazonaws\.com\/publishflow\/|doubleclick\.net\/pfadx\/nbcu\.nbc\/|doubleclick\.net\/pfadx\/www\.tv3\.co\.nz|amazonaws\.com\/ownlocal\-|bluehost\-cdn\.com\/media\/partner\/images\/|doubleclick\.net\/pfadx\/ddm\.ksl\/|doubleclick\.net\/xbbe\/creative\/vast|theolympian\.com\/static\/images\/weathersponsor\/|pussycash\.com\/content\/banners\/|doubleclick\.net\/pfadx\/tmg\.telegraph\.|betwaypartners\.com\/affiliate_media\/|filedownloader\.net\/design\/|ad\.atdmt\.com\/m\/|mrc\.org\/sites\/default\/files\/uploads\/images\/Collusion_Banner|cdn77\.org\/tags\/|doubleclick\.net\/pfadx\/ccr\.|ebaystatic\.com\/aw\/signin\/ebay\-signin\-toyota\-|express\.de\/analytics\/|techkeels\.com\/creatives\/|allanalpass\.com\/track\/|adm\.fwmrm\.net\/p\/mtvn_live\/|urlcash\.org\/banners\/|doubleclick\.net\/pfadx\/sugar\.poptv\/|doubleclick\.net\/pfadx\/ng\.videoplayer\/|updatetube\.com\/iframes\/|staticneo\.com\/neoassets\/iframes\/leaderboard_bottom\.|cloudfront\.net\/performable\/|doubleclick\.net\/pfadx\/muzuoffsite\/|twitch\.tv\/track\/|embed\.docstoc\.com\/Flash\.asmx\/StoreReffer|static\.twincdn\.com\/special\/script\.packed|bigrock\.in\/affiliate\/|doubleclick\.net\/pfadx\/CBS\.|publicbroadcasting\.net\/analytics\/|sitegiant\.my\/affiliate\/|mail\.ru\/count\/|singlehop\.com\/affiliates\/|tlavideo\.com\/affiliates\/|browsershots\.org\/static\/images\/creative\/|obox\-design\.com\/affiliate\-banners\/|static\.twincdn\.com\/special\/license\.packed|theseblogs\.com\/visitScript\/|metromedia\.co\.za\/bannersys\/banners\/|h2porn\.com\/contents\/content_sources\/|hulkload\.com\/b\/|sulia\.com\/papi\/sulia_partner\.js\/|beacons\.vessel\-static\.com\/xff|imagecarry\.com\/down|apkmaza\.net\/wp\-content\/uploads\/|chefkoch\.de\/counter|doubleclick\.net\/pfadx\/ctv\.spacecast\/|doubleclick\.net\/pfadx\/nfl\.|doubleclick\.net\/pfadx\/csn\.|doubleclick\.net\/pfadx\/muzumain\/|dnsstuff\.com\/dnsmedia\/images\/ft\.banner\.|drift\.com\/track|share\-online\.biz\/affiliate\/|groupon\.com\/tracking|goldmoney\.com\/~\/media\/Images\/Banners\/|vidible\.tv\/placement\/vast\/|e\-tailwebstores\.com\/accounts\/default1\/banners\/|google\-analytics\.com\/collect|thebull\.com\.au\/admin\/uploads\/banners\/|ibtimes\.com\/banner\/|brettterpstra\.com\/wp\-content\/uploads\/|110\.45\.173\.103\/ad\/|celebstoner\.com\/assets\/components\/bdlistings\/uploads\/|terra\.com\.br\/metrics\/|storage\.to\/affiliate\/|creativecdn\.com\/pix\/|olark\.com\/track\/|pedestrian\.tv\/_crunk\/wp\-content\/files_flutter\/|camwhores\.tv\/banners\/|debtconsolidationcare\.com\/affiliate\/tracker\/|dnevnik\.si\/tracker\/|mail\.ru\/counter|dealextreme\.com\/affiliate_upload\/|gaccmidwest\.org\/uploads\/tx_bannermanagement\/|epictv\.com\/sites\/default\/files\/290x400_|appinthestore\.com\/click\/|vivatube\.com\/upload\/banners\/|expertreviews\.co\.uk\/widget\/|usps\.com\/survey\/|filez\.cutpaid\.com\/336v|wonderlabs\.com\/affiliate_pro\/banners\/|doubleclick\.net\/adx\/tsg\.|videos\.com\/click|1movies\.to\/site\/videoroller|thenude\.eu\/media\/mxg\/|suite101\.com\/tracking\/|thesundaily\.my\/sites\/default\/files\/twinskyscrapers|aerotime\.aero\/upload\/banner\/|freemoviestream\.xyz\/wp\-content\/uploads\/|nfl\.com\/assets\/images\/hp\-poweredby\-|slack\.com\/beacon\/|wwe\.com\/sites\/all\/modules\/wwe\/wwe_analytics\/|media\.enimgs\.net\/brand\/files\/escalatenetwork\/|doubleclick\.net\/pfadx\/ssp\.kgtv\/|bruteforcesocialmedia\.com\/affiliates\/|cnzz\.com\/stat\.|couptopia\.com\/affiliate\/|flixcart\.com\/affiliate\/|infibeam\.com\/affiliate\/|lawdepot\.com\/affiliate\/|seedsman\.com\/affiliate\/|doubleclick\.net\/N5479\/pfadx\/ctv\.|plugins\.longtailvideo\.com\/yourlytics|sectools\.org\/shared\/images\/p\/|media\.domainking\.ng\/media\/|homoactive\.tv\/banner\/|newoxfordreview\.org\/banners\/ad\-|doubleclick\.net\/pfadx\/bet\.com\/|morningstaronline\.co\.uk\/offsite\/progressive\-listings\/|dota\-trade\.com\/img\/branding_|knco\.com\/wp\-content\/uploads\/wpt\/|yyv\.co\/track\/|doubleclick\.net\/pfadx\/storm\.no\/|sacbee\.com\/static\/dealsaver\/|amazon\.com\/gp\/yourstore\/recs\/|whozacunt\.com\/images\/banner_|ppc\-coach\.com\/jamaffiliates\/|petri\.co\.il\/wp\-content\/uploads\/banner1000x75_|petri\.co\.il\/wp\-content\/uploads\/banner700x475_|zap2it\.com\/wp\-content\/themes\/overmind\/js\/zcode\-|yea\.xxx\/img\/creatives\/|sapeople\.com\/wp\-content\/uploads\/wp\-banners\/|mixpanel\.com\/track|dx\.com\/affiliate\/|itweb\.co\.za\/logos\/|inhumanity\.com\/cdn\/affiliates\/|accuradio\.com\/static\/track\/|taboola\.com\/tb|doubleclick\.net\/adx\/CBS\.|doubleclick\.net\/json|thenude\.eu\/affiliates\/|pwpwpoker\.com\/images\/banners\/|whistleout\.com\.au\/imagelibrary\/ads\/wo_skin_|yahooapis\.com\/get\/Valueclick\/CapAnywhere\.getAnnotationCallback|russian\-dreams\.net\/static\/js\/|nmap\.org\/shared\/images\/p\/|seclists\.org\/shared\/images\/p\/|ru4\.com\/click|preisvergleich\.de\/setcookie\/|vator\.tv\/tracking\/|desert\.ru\/tracking\/|putpat\.tv\/tracking|static\.multiplayuk\.com\/images\/w\/w\-|ironsquid\.tv\/data\/uploads\/sponsors\/|videovalis\.tv\/tracking\/|dpbolvw\.net\/image\-|worddictionary\.co\.uk\/static\/\/inpage\-affinity\/|anrdoezrs\.net\/image\-|iradio\.ie\/assets\/img\/backgrounds\/|doubleclick\.net\/adi\/|vitalmtb\.com\/assets\/vital\.aba\-|hottubeclips\.com\/stxt\/banners\/|themis\-media\.com\/media\/global\/images\/cskins\/|kontextr\.eu\/content\/track|c21media\.net\/wp\-content\/plugins\/sam\-images\/|punterlink\.co\.uk\/images\/storage\/siteban|recomendedsite\.com\/addon\/upixel\/|sextvx\.com\/static\/images\/tpd\-|metroweekly\.com\/tools\/blog_add_visitor\/|tsite\.jp\/static\/analytics\/|myanimelist\.cdn\-dena\.com\/images\/affiliates\/|sdamgia\.ru\/img\/blockadblock_|babyblog\.ru\/pixel|citeulike\.org\/static\/campaigns\/|ians\.in\/iansad\/|nation\.sc\/images\/banners\/|inphonic\.com\/tracking\/|theday\.com\/assets\/images\/sponsorlogos\/|nspmotion\.com\/tracking\/|foxadd\.com\/addon\/upixel\/|dailymail\.co\.uk\/tracking\/|hqq\.watch\/js\/betterj\/|optimum\.net\/utilities\/doubleclicktargeting|media\.complex\.com\/videos\/prerolls\/|ed\-protect\.org\/cdn\-cgi\/apps\/head\/|wikipedia\.org\/beacon\/|ask\.com\/servlets\/ulog|rbth\.ru\/widget\/|adyou\.me\/bug\/adcash|saabsunited\.com\/wp\-content\/uploads\/180x460_|saabsunited\.com\/wp\-content\/uploads\/werbung\-|zambiz\.co\.zm\/banners\/|tehrantimes\.com\/banner\/|theatm\.info\/images\/|mightydeals\.com\/widget|worldradio\.ch\/site_media\/banners\/|proxysolutions\.net\/affiliates\/|avira\.com\/site\/datatracking|expekt\.com\/affiliates\/|swurve\.com\/affiliates\/|axandra\.com\/affiliates\/|examiner\.com\/sites\/all\/modules\/custom\/ex_stats\/|doubleclick\.net\/adx\/wn\.loc\.|blissful\-sin\.com\/affiliates\/|singlemuslim\.com\/affiliates\/|mangaupdates\.com\/affiliates\/|bruteforceseo\.com\/affiliates\/|salemwebnetwork\.com\/Stations\/images\/SiteWrapper\/|graduateinjapan\.com\/affiliates\/|americanfreepress\.net\/assets\/images\/Banner_|multiupload\.nl\/popunder\/|uploaded\.to\/img\/public\/|lipsy\.co\.uk\/_assets\/images\/skin\/tracking\/|bitbond\.com\/affiliate\-program\/|204\.140\.25\.247\/ads\/|visa\.com\/logging\/logEvent|smn\-news\.com\/images\/banners\/|porn2blog\.com\/wp\-content\/banners\/|getadblock\.com\/images\/adblock_banners\/|djmag\.co\.uk\/sites\/default\/files\/takeover\/|euphonik\.dj\/img\/sponsors\-|eventful\.com\/tools\/click\/url|brandcdn\.com\/pixel\/|vpnarea\.com\/affiliate\/|borrowlenses\.com\/affiliate\/|thereadystore\.com\/affiliate\/|kommersant\.uk\/banner_stats|conde\.io\/beacon|allmovieportal\.com\/dynbanner\.|omsnative\.de\/tracking\/|channel4\.com\/assets\/programmes\/images\/originals\/|cloudfront\.net\/analyticsengine\/|casti\.tv\/adds\/|dailymail\.co\.uk\/i\/pix\/ebay\/|reuters\.com\/tracker\/|distrowatch\.com\/images\/kokoku\/|ukcast\.tv\/adds\/|ad2links\.com\/js\/|onescreen\.net\/os\/static\/pixels\/|live\-porn\.tv\/adds\/|djmag\.com\/sites\/default\/files\/takeover\/|freeporn\.to\/wpbanner\/|xscores\.com\/livescore\/banners\/|avito\.ru\/stat\/|abplive\.in\/analytics\/|slide\.com\/tracker\/|go\.com\/stat\/|swagmp3\.com\/cdn\-cgi\/pe\/|cdn\.69games\.xxx\/common\/images\/friends\/|skroutz\.gr\/analytics\/|myiplayer\.eu\/ad|ovpn\.to\/ovpn\.to\/banner\/|b2w\.io\/event\/|ziffstatic\.com\/jst\/zdvtools\.|talkphotography\.co\.uk\/images\/externallogos\/banners\/|popeoftheplayers\.eu\/ad|eccie\.net\/buploads\/|vipbox\.tv\/js\/layer\-|ejpress\.org\/img\/banners\/|whitepages\.ae\/images\/UI\/SRA\/|whitepages\.ae\/images\/UI\/SRB\/|whitepages\.ae\/images\/UI\/WS\/|toolslib\.net\/assets\/img\/a_dvt\/|watchuseek\.com\/media\/1900x220_|agitos\.de\/content\/track|webdesignerdepot\.com\/wp\-content\/plugins\/md\-popup\/|ball2win\.com\/Affiliate\/|timesinternet\.in\/ad\/|getreading\.co\.uk\/static\/img\/bg_takeover_|customerlobby\.com\/ctrack\-|pixazza\.com\/track\/|sysomos\.com\/track\/|tamilwire\.org\/images\/banners3\/|luminate\.com\/track\/|picbucks\.com\/track\/|dailyhome\.com\/leaderboard_banner|annistonstar\.com\/leaderboard_banner|targetspot\.com\/track\/|turnsocial\.com\/track\/|glam\.com\/gad\/|va\.tawk\.to\/log|doubleclick\.net\/pfadx\/trb\.|sweed\.to\/affiliates\/|s24cloud\.net\/metrics\/|carambo\.la\/analytics\/|gameblog\.fr\/images\/ablock\/|majorgeeks\.com\/images\/download_sd_|nijobfinder\.co\.uk\/affiliates\/|desperateseller\.co\.uk\/affiliates\/|geometria\.tv\/banners\/|ziffstatic\.com\/jst\/zdsticky\.|ximagehost\.org\/myman\.|aftonbladet\.se\/blogportal\/view\/statistics|digitalsatellite\.tv\/banners\/|alooma\.io\/track\/|relink\.us\/images\/|uploading\.com\/static\/banners\/|amazonaws\.com\/fstrk\.net\/|gaccny\.com\/uploads\/tx_bannermanagement\/|amy\.gs\/track\/|dyo\.gs\/track\/|ahk\-usa\.com\/uploads\/tx_bannermanagement\/|gaccwest\.com\/uploads\/tx_bannermanagement\/|gaccsouth\.com\/uploads\/tx_bannermanagement\/|concealednation\.org\/sponsors\/|oasap\.com\/images\/affiliate\/|1320wils\.com\/assets\/images\/promo%20banner\/|videogame\.it\/a\/logview\/|bhaskar\.com\/ads\/|needle\.com\/pageload|movie2kto\.ws\/popup|sciencecareers\.org\/widget\/|intercom\.io\/gtm_tracking\/|tvducky\.com\/imgs\/graboid\.|nigeriafootball\.com\/img\/affiliate_|dailymotion\.com\/logger\/|urbanvelo\.org\/sidebarbanner\/|s\.holm\.ru\/stat\/|hentaistream\.com\/wp\-includes\/images\/bg\-|itworld\.com\/slideshow\/iframe\/topimu\/|piano\.io\/tracker\/|mcvuk\.com\/static\/banners\/|shinypics\.com\/blogbanner\/|theleader\.info\/banner|anti\-scam\.org\/abanners\/|chelsey\.co\.nz\/uploads\/Takeovers\/|lgoat\.com\/cdn\/amz_|armenpress\.am\/static\/add\/|journal\-news\.net\/annoyingpopup\/|bbcchannels\.com\/workspace\/uploads\/|guru99\.com\/images\/adblocker\/|bits\.wikimedia\.org\/geoiplookup|text\-compare\.com\/media\/global_vision_banner_|1page\.co\.za\/affiliate\/|ehow\.com\/services\/jslogging\/log\/|joblet\.jp\/javascripts\/|early\-birds\.fr\/tracker\/|lumfile\.com\/lumimage\/ourbanner\/|chaturbate\.com\/sitestats\/openwindow\/|safarinow\.com\/affiliate\-zone\/|totalcmd\.pl\/img\/nucom\.|totalcmd\.pl\/img\/olszak\.|peggo\.tv\/ad\/|daily\-mail\.co\.zm\/images\/banners\/|hqfooty\.tv\/ad|thelodownny\.com\/leslog\/ads\/|tvbrowser\.org\/logo_df_tvsponsor_|traq\.li\/tracker\/|googlesyndication\.com\/ddm\/|galleries\.bz\/track\/|thefind\.com\/page\/sizelog|justporno\.tv\/ad\/|trustedreviews\.com\/mobile\/widgets\/html\/promoted\-phones|doubleclick\.net\/pfadx\/comedycentral\.|develop\-online\.net\/static\/banners\/|net\-parade\.it\/tracker\/|frenchradiolondon\.com\/data\/carousel\/|graboid\.com\/affiliates\/|pixel\.indieclicktv\.com\/annonymous\/|pcmall\.co\.za\/affiliates\/|yandex\.ru\/cycounter|4pda\.ru\/stat\/|tshirthell\.com\/img\/affiliate_section\/|go2cdn\.org\/brand\/|gamefront\.com\/wp\-content\/plugins\/tracker\/|jenningsforddirect\.co\.uk\/sitewide\/extras\/|lowendbox\.com\/wp\-content\/themes\/leb\/banners\/|kamcity\.com\/menu\/banners\/|amazonaws\.com\/btrb\-prd\-banners\/|wiwo\.de\/analytics\/|karelia\.info\/counter\/|fr\-online\.de\/analytics\/|youtube\.com\/user\/Blank|facebook\.com\/plugins\/|youtube\.com\/api\/|porntube\.com[^\w.%-](?=([\s\S]*?\/track))\1|facebook\.com[^\w.%-](?=([\s\S]*?\/tracking\.js))\2|bitgravity\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\3|youporn\.com[^\w.%-](?=([\s\S]*?\/tracker\.js))\4|clickfunnels\.com[^\w.%-](?=([\s\S]*?\/track))\5|ninemsn\.com\.au[^\w.%-](?=([\s\S]*?\.tracking\.udc\.))\6|cloudfront\.net(?=([\s\S]*?\/tracker\.js))\7|9msn\.com\.au[^\w.%-](?=([\s\S]*?\/tracking\/))\8|buzzfeed\.com[^\w.%-](?=([\s\S]*?\/tracker\.js))\9|gowatchit\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\10|reevoo\.com[^\w.%-](?=([\s\S]*?\/track\/))\11|svcs\.ebay\.com\/services\/search\/FindingService\/(?=([\s\S]*?[^\w.%-]affiliate\.tracking))\12|skype\.com[^\w.%-](?=([\s\S]*?\/track_channel\.js))\13|livefyre\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\14|goadv\.com[^\w.%-](?=([\s\S]*?\/track\.js))\15|msn\.com[^\w.%-](?=([\s\S]*?\/track\.js))\16|forbes\.com[^\w.%-](?=([\s\S]*?\/track\.php))\17|dealer\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\18|zdf\.de[^\w.%-](?=([\s\S]*?\/tracking))\19|dealer\.com[^\w.%-](?=([\s\S]*?\/tracker\/))\20|marketingpilgrim\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/trackur\.com\-))\21|staticwhich\.co\.uk\/assets\/(?=([\s\S]*?\/track\.js))\22|euroleague\.tv[^\w.%-](?=([\s\S]*?\/tracking\.js))\23|azurewebsites\.net[^\w.%-](?=([\s\S]*?\/mnr\-mediametrie\-tracking\-))\24|partypoker\.com[^\w.%-](?=([\s\S]*?\/tracking\-))\25|vectorstock\.com[^\w.%-](?=([\s\S]*?\/tracking))\26|doubleclick\.net[^\w.%-](?=([\s\S]*?\/trackimp\/))\27|lemde\.fr[^\w.%-](?=([\s\S]*?\/tracking\/))\28|akamai\.net[^\w.%-](?=([\s\S]*?\/sitetracking\/))\29|gazzettaobjects\.it[^\w.%-](?=([\s\S]*?\/tracking\/))\30|volkswagen\-italia\.it[^\w.%-](?=([\s\S]*?\/tracking\/))\31|fyre\.co[^\w.%-](?=([\s\S]*?\/tracking\/))\32|comparis\.ch[^\w.%-](?=([\s\S]*?\/Tracking\/))\33|trackitdown\.net\/skins\/(?=([\s\S]*?_campaign\/))\34|ringostrack\.com[^\w.%-](?=([\s\S]*?\/amazon\-buy\.gif))\35|typepad\.com[^\w.%-](?=([\s\S]*?\/stats))\36|kat2\.biz\/(?=([\s\S]*?))\37|kickass2\.biz\/(?=([\s\S]*?))\38|doubleclick\.net[^\w.%-](?=([\s\S]*?\/ad\/))\39|adf\.ly\/(?=([\s\S]*?\.php))\40|doubleclick\.net[^\w.%-](?=([\s\S]*?\/adj\/))\41|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/adawe\-))\42|images\-amazon\.com[^\w.%-](?=([\s\S]*?\/Analytics\-))\43|r18\.com[^\w.%-](?=([\s\S]*?\/banner\/))\44|hulkshare\.com[^\w.%-](?=([\s\S]*?\/adsmanager\.js))\45|allmyvideos\.net\/(?=([\s\S]*?%))\46|allmyvideos\.net\/(?=([\s\S]*?))\47|images\-amazon\.com\/images\/(?=([\s\S]*?\/banner\/))\48|torrentproject\.ch\/(?=([\s\S]*?))\49|rackcdn\.com[^\w.%-](?=([\s\S]*?\/analytics\.js))\50|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/adaptvjw5\-))\51|openload\.co[^\w.%-](?=([\s\S]*?\/_))\52|freebunker\.com[^\w.%-](?=([\s\S]*?\/pops\.js))\53|213\.174\.140\.76[^\w.%-](?=([\s\S]*?\/js\/msn\.js))\54|amazonaws\.com[^\w.%-](?=([\s\S]*?\/pageviews))\55|thevideo\.me\/(?=([\s\S]*?\.php))\56|taboola\.com[^\w.%-](?=([\s\S]*?\/log\/))\57|xhcdn\.com[^\w.%-](?=([\s\S]*?\/ads_))\58|liutilities\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\59|urlcash\.net\/random(?=([\s\S]*?\.php))\60|oload\.tv[^\w.%-](?=([\s\S]*?\/_))\61|quantserve\.com[^\w.%-](?=([\s\S]*?\.swf))\62|blogsmithmedia\.com[^\w.%-](?=([\s\S]*?\/amazon_))\63|ifilm\.com\/website\/(?=([\s\S]*?_skin_))\64|freebunker\.com[^\w.%-](?=([\s\S]*?\/oc\.js))\65|kitguru\.net\/wp\-content\/uploads\/(?=([\s\S]*?\-Skin\.))\66|yimg\.com[^\w.%-](?=([\s\S]*?\/sponsored\.js))\67|imgflare\.com[^\w.%-](?=([\s\S]*?\/splash\.php))\68|bestofmedia\.com[^\w.%-](?=([\s\S]*?\/beacons\/))\69|skypeassets\.com[^\w.%-](?=([\s\S]*?\/inclient\/))\70|thecatholicuniverse\.com[^\w.%-](?=([\s\S]*?\-ad\.))\71|i3investor\.com[^\w.%-](?=([\s\S]*?\/partner\/))\72|static\.(?=([\s\S]*?\.criteo\.net\/js\/duplo[^\w.%-]))\73|paypal\.com[^\w.%-](?=([\s\S]*?\/pixel\.gif))\74|videogamesblogger\.com[^\w.%-](?=([\s\S]*?\/scripts\/takeover\.js))\75|redtubefiles\.com[^\w.%-](?=([\s\S]*?\/banner\/))\76|thevideo\.me\/(?=([\s\S]*?_))\77|meetlocals\.com[^\w.%-](?=([\s\S]*?popunder))\78|cloudzer\.net[^\w.%-](?=([\s\S]*?\/banner\/))\79|tumblr\.com[^\w.%-](?=([\s\S]*?\/sponsored_))\80|tumblr\.com[^\w.%-](?=([\s\S]*?_sponsored_))\81|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/ltas\-))\82|xhcdn\.com[^\w.%-](?=([\s\S]*?\/sponsor\-))\83|media\-imdb\.com[^\w.%-](?=([\s\S]*?\/affiliates\/))\84|widgetserver\.com[^\w.%-](?=([\s\S]*?\/image\.gif))\85|avg\.com[^\w.%-](?=([\s\S]*?\/stats\.js))\86|aolcdn\.com[^\w.%-](?=([\s\S]*?\/beacon\.min\.js))\87|facebook\.com\/ajax\/(?=([\s\S]*?\/log\.php))\88|static\.(?=([\s\S]*?\.criteo\.net\/images[^\w.%-]))\89|speedcafe\.com[^\w.%-](?=([\s\S]*?\-banner\-))\90|redtube\.com[^\w.%-](?=([\s\S]*?\/banner\/))\91|googleapis\.com[^\w.%-](?=([\s\S]*?\/gen_204))\92|eweek\.com[^\w.%-](?=([\s\S]*?\/sponsored\-))\93|images\-amazon\.com\/images\/(?=([\s\S]*?\/ga\.js))\94|imagefruit\.com[^\w.%-](?=([\s\S]*?\/pops\.js))\95|google\.com[^\w.%-](?=([\s\S]*?\/log))\96|freebunker\.com[^\w.%-](?=([\s\S]*?\/raw\.js))\97|idg\.com\.au\/images\/(?=([\s\S]*?_promo))\98|arstechnica\.net[^\w.%-](?=([\s\S]*?\/sponsor\-))\99|yimg\.com[^\w.%-](?=([\s\S]*?\/flash\/promotions\/))\100|24hourwristbands\.com\/(?=([\s\S]*?\.googleadservices\.com\/))\101|yimg\.com[^\w.%-](?=([\s\S]*?\/ywa\.js))\102|adswizz\.com\/adswizz\/js\/SynchroClient(?=([\s\S]*?\.js))\103|googlesyndication\.com[^\w.%-](?=([\s\S]*?\/googlevideoadslibraryas3\.swf))\104|armorgames\.com[^\w.%-](?=([\s\S]*?\/banners\/))\105|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/FME\-Red\-CAP\.jpg))\106|widgetserver\.com[^\w.%-](?=([\s\S]*?\/quantcast\.swf))\107|turner\.com[^\w.%-](?=([\s\S]*?\/ads\/))\108|doubleclick\.net\/adx\/(?=([\s\S]*?\.NPR\.MUSIC\/))\109|thecatholicuniverse\.com[^\w.%-](?=([\s\S]*?\-advert\-))\110|postaffiliatepro\.com[^\w.%-](?=([\s\S]*?\/banners\/))\111|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/banner\.gif))\112|gfi\.com\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\-BlogBanner))\113|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/ibs\.orl\.news\/))\114|facebook\.com(?=([\s\S]*?\/impression\.php))\115|virginmedia\.com[^\w.%-](?=([\s\S]*?\/analytics\/))\116|lfcimages\.com[^\w.%-](?=([\s\S]*?\/partner\-))\117|johngaltfla\.com\/wordpress\/wp\-content\/uploads\/(?=([\s\S]*?\/TB2K_LOGO\.jpg))\118|johngaltfla\.com\/wordpress\/wp\-content\/uploads\/(?=([\s\S]*?\/jmcs_specaialbanner\.jpg))\119|adamvstheman\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/AVTM_banner\.jpg))\120|ibtimes\.com[^\w.%-](?=([\s\S]*?\/sponsor_))\121|financialsamurai\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/sliced\-alternative\-10000\.jpg))\122|phpbb\.com[^\w.%-](?=([\s\S]*?\/images\/hosting\/hostmonster\-downloads\.gif))\123|pimpandhost\.com\/static\/i\/(?=([\s\S]*?\-pah\.jpg))\124|thechive\.files\.wordpress\.com[^\w.%-](?=([\s\S]*?\-wallpaper\-))\125|amazonaws\.com[^\w.%-](?=([\s\S]*?\/Test_oPS_Script_Loads))\126|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/team\.car\/))\127|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/team\.dal\/))\128|yimg\.com[^\w.%-](?=([\s\S]*?\/fairfax\/))\129|imgbox\.com\/(?=([\s\S]*?\.html))\130|newstatesman\.com\/sites\/all\/themes\/(?=([\s\S]*?_1280x2000\.))\131|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/PW\-Ad\.jpg))\132|cdmagurus\.com\/img\/(?=([\s\S]*?\.gif))\133|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/app\.ytpwatch\.))\134|nichepursuits\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/long\-tail\-pro\-banner\.gif))\135|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/DeadwoodStove\-PW\.gif))\136|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/embed\.ytpwatch\.))\137|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.MTV\-Viacom\/))\138|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.NBCUNI\.COM\/))\139|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/ccr\.newyork\.))\140|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.NBCUNIVERSAL\-CNBC\/))\141|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/jihad\.jpg))\142|berush\.com\/images\/(?=([\s\S]*?_semrush_))\143|copblock\.org\/wp\-content\/uploads\/(?=([\s\S]*?\/covert\-handcuff\-key\-AD\-))\144|queermenow\.net\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\-Banner))\145|opencurrency\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-aocs\-sidebar\-commodity\-bank\.png))\146|thehealthcareblog\.com\/files\/(?=([\s\S]*?\/American\-Resident\-Project\-Logo\-))\147|mrc\.org[^\w.%-](?=([\s\S]*?\/Collusion_Banner300x250\.jpg))\148|nufc\.com[^\w.%-](?=([\s\S]*?\/The%20Gate_NUFC\.com%20banner_%2016\.8\.13\.gif))\149|flixster\.com[^\w.%-](?=([\s\S]*?\/analytics\.))\150|purpleporno\.com\/pop(?=([\s\S]*?\.js))\151|thecommonsenseshow\.com\/siteupload\/(?=([\s\S]*?\/adsqmetals\.jpg))\152|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/com\.ytpwatch\.))\153|linkbird\.com\/static\/upload\/(?=([\s\S]*?\/banner\/))\154|allhiphop\.com\/site_resources\/ui\-images\/(?=([\s\S]*?\-conduit\-banner\.gif))\155|reddit\.com[^\w.%-](?=([\s\S]*?_sponsor\.png))\156|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Johnson\-Grow\-Lights\.gif))\157|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Judge\-Lenny\-001\.jpg))\158|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.NBCUNIVERSAL\/))\159|marijuanapolitics\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/icbc1\.png))\160|marijuanapolitics\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/icbc2\.png))\161|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/team\.sd\/))\162|bitcoinreviewer\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/banner\-luckybit\.jpg))\163|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/apmgoldmembership250x250\.jpg))\164|cooksunited\.co\.uk\/counter(?=([\s\S]*?\.php))\165|walshfreedom\.com[^\w.%-](?=([\s\S]*?\/liberty\-luxury\.png))\166|uflash\.tv[^\w.%-](?=([\s\S]*?\/affiliates\/))\167|queermenow\.net\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\/banner))\168|rghost\.ru\/download\/a\/(?=([\s\S]*?\/banner_download_))\169|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?_250x150\.png))\170|cloudfront\.net(?=([\s\S]*?\/trk\.js))\171|db\.com[^\w.%-](?=([\s\S]*?\/stats\.js))\172|zoover\.(?=([\s\S]*?\/shared\/bannerpages\/darttagsbanner\.aspx))\173|mydramalist\.info[^\w.%-](?=([\s\S]*?\/affiliates\/))\174|netbiscuits\.net[^\w.%-](?=([\s\S]*?\/analytics\/))\175|searchenginejournal\.com[^\w.%-](?=([\s\S]*?\/sponsored\-))\176|telegraphindia\.com[^\w.%-](?=([\s\S]*?\/banners\/))\177|drivereasy\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/sidebar\-DriverEasy\-buy\.jpg))\178|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.ABC\.com\/))\179|player\.screenwavemedia\.com[^\w.%-](?=([\s\S]*?\/ova\-jw\.swf))\180|adz\.lk[^\w.%-](?=([\s\S]*?_ad\.))\181|ragezone\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/HV\-banner\-300\-200\.jpg))\182|nfl\.com[^\w.%-](?=([\s\S]*?\/page\-background\-image\.jpg))\183|tipico\.(?=([\s\S]*?\/affiliate\/))\184|preppersmallbiz\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/PSB\-Support\.jpg))\185|activewin\.com[^\w.%-](?=([\s\S]*?\/blaze_static2\.gif))\186|static\.ow\.ly[^\w.%-](?=([\s\S]*?\/click\.gz\.js))\187|techinsider\.net\/wp\-content\/uploads\/(?=([\s\S]*?\-300x500\.))\188|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?_Side_Banner\.))\189|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?_Side_Banner_))\190|doubleclick\.net\/(?=([\s\S]*?\/pfadx\/lin\.))\191|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.ESPN\/))\192|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.muzu\/))\193|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/tsepulveda\-1\.jpg))\194|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.BLIPTV\/))\195|doubleclick\.net\/pfadx\/(?=([\s\S]*?\/kidstv\/))\196|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/muzumain\/))\197|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.MCNONLINE\/))\198|doubleclick\.net\/pfadx\/(?=([\s\S]*?CBSINTERACTIVE\/))\199|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.VIACOMINTERNATIONAL\/))\200|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.WALTDISNEYINTERNETGROU\/))\201|iimg\.in[^\w.%-](?=([\s\S]*?\/sponsor_))\202|thecommonsenseshow\.com\/siteupload\/(?=([\s\S]*?\/nightvisionadnew\.jpg))\203|saf\.org\/wp\-content\/uploads\/(?=([\s\S]*?\/theGunMagbanner\.png))\204|data\.ninemsn\.com\.au\/(?=([\s\S]*?GetAdCalls))\205|youku\.com[^\w.%-](?=([\s\S]*?\/click\.php))\206|ebaystatic\.com\/aw\/pics\/signin\/(?=([\s\S]*?_signInSkin_))\207|thehealthcareblog\.com\/files\/(?=([\s\S]*?\/THCB\-Validic\-jpg\-opt\.jpg))\208|totallylayouts\.com[^\w.%-](?=([\s\S]*?\/users\-online\-counter\/online\.js))\209|video\.abc\.com[^\w.%-](?=([\s\S]*?\/promos\/))\210|grouponcdn\.com[^\w.%-](?=([\s\S]*?\/affiliate_widget\/))\211|freebunker\.com[^\w.%-](?=([\s\S]*?\/layer\.js))\212|yimg\.com\/cv\/(?=([\s\S]*?\/billboard\/))\213|saf\.org\/wp\-content\/uploads\/(?=([\s\S]*?\/women_guns192x50\.png))\214|s\-assets\.tp\-cdn\.com\/widgets\/(?=([\s\S]*?\/vwid\/))\215(?=([\s\S]*?\.html))\216|upcat\.custvox\.org\/survey\/(?=([\s\S]*?\/countOpen\.gif))\217|bestvpn\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/mosttrustedname_260x300_))\218|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/gorillabanner728\.gif))\219|cannabisjobs\.us\/wp\-content\/uploads\/(?=([\s\S]*?\/OCWeedReview\.jpg))\220|images\-pw\.secureserver\.net[^\w.%-](?=([\s\S]*?_))\221(?=([\s\S]*?\.))\222|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/sensi2\.jpg))\223|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/cannafo\.jpg))\224|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/WeedSeedShop\.jpg))\225|upload\.ee\/image\/(?=([\s\S]*?\/B_descarga_tipo12\.gif))\226|pornsharing\.com\/App_Themes\/pornsharianew\/js\/adppornsharia(?=([\s\S]*?\.js))\227|pornsharing\.com\/App_Themes\/pornsharingnew\/js\/adppornsharia(?=([\s\S]*?\.js))\228|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/dakine420\.png))\229|cardsharing\.info\/wp\-content\/uploads\/(?=([\s\S]*?\/ALLS\.jpg))\230|googlesyndication\.com[^\w.%-](?=([\s\S]*?\/domainpark\.cgi))\231|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-250x250\.jpg))\232|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?_250x250\.jpg))\233|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?_300x400_))\234|thepreparednessreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?_175x175\.jpg))\235|thepreparednessreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?_185x185\.jpg))\236|starofmysore\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\-karbonn\.))\237|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/ssp\.wews\/))\238|malaysiabay\.org[^\w.%-](?=([\s\S]*?creatives\.php))\239|maciverse\.mangoco\.netdna\-cdn\.com[^\w.%-](?=([\s\S]*?banner))\240|wp\.com\/adnetsreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?banner))\241|content\.ad\/Scripts\/widget(?=([\s\S]*?\.aspx))\242|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/free_ross\.jpg))\243|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/cmn_complextv\/))\244|complexmedianetwork\.com[^\w.%-](?=([\s\S]*?\/toolbarlogo\.png))\245|lfgcomic\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/PageSkin_))\246|heyjackass\.com\/wp\-content\/uploads\/(?=([\s\S]*?_300x225_))\247|nextbigwhat\.com\/wp\-content\/uploads\/(?=([\s\S]*?ccavenue))\248|sourcefed\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/netflix4\.jpg))\249|originalweedrecipes\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-Medium\.jpg))\250|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.sevenload\.com_))\251|doubleclick\.net\/adx\/(?=([\s\S]*?\.NPR\/))\252|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/180_350\.))\253|avito\.ru[^\w.%-](?=([\s\S]*?\/some\-pretty\-script\.js))\254|ebaystatic\.com\/aw\/signin\/(?=([\s\S]*?_wallpaper_))\255|sify\.com[^\w.%-](?=([\s\S]*?\/gads_))\256|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/scrogger\.gif))\257|saabsunited\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\-))\258|saabsunited\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\.))\259|saabsunited\.com\/wp\-content\/uploads\/(?=([\s\S]*?_banner_))\260|raysindex\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/dolmansept2012flash\.swf))\261|survivaltop50\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Survival215x150Link\.png))\262|morefree\.net\/wp\-content\/uploads\/(?=([\s\S]*?\/mauritanie\.gif))\263|lawprofessorblogs\.com\/responsive\-template\/(?=([\s\S]*?advert\.))\264|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/dynamic_banner_))\265|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/xbt\-social\.png))\266|mypbrand\.com\/wp\-content\/uploads\/(?=([\s\S]*?banner))\267|russiasexygirls\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/cb_))\268|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/allserviceslogo\.gif))\269|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/xbt\.jpg))\270|thejointblog\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-235x))\271|capitolfax\.com\/wp\-content\/(?=([\s\S]*?ad\.))\272|libero\.it[^\w.%-](?=([\s\S]*?\/counter\.php))\273|russiasexygirls\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/727x90))\274|gaystarnews\.com[^\w.%-](?=([\s\S]*?\-sponsor\.))\275|doubleclick\.net[^\w.%-](?=([\s\S]*?\/adi\/))\276|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/cloudbet_))\277|thepreparednessreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/250x125\-))\278|freedom\.com[^\w.%-](?=([\s\S]*?\/analytics\/))\279|capitolfax\.com\/wp\-content\/(?=([\s\S]*?Ad_))\280|afcdn\.com[^\w.%-](?=([\s\S]*?\/ova\-jw\.swf))\281|dailyanimation\.studio[^\w.%-](?=([\s\S]*?\/banners\.))\282|signup\.advance\.net[^\w.%-](?=([\s\S]*?affiliate))\283|pastime\.biz[^\w.%-](?=([\s\S]*?\/personalad))\284(?=([\s\S]*?\.jpg))\285|thecompassionchronicles\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\-))\286|thecompassionchronicles\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\.))\287|seedr\.ru[^\w.%-](?=([\s\S]*?\/stats\/))\288|foxandhoundsdaily\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-AD\.gif))\289|gmstatic\.net[^\w.%-](?=([\s\S]*?\/amazonbadge\.png))\290|newsonjapan\.com[^\w.%-](?=([\s\S]*?\/banner\/))\291|uniblue\.com[^\w.%-](?=([\s\S]*?\/affiliates\/))\292|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.nbc\.com\/))\293|structuredchannel\.com\/sw\/swchannel\/images\/MarketingAssets\/(?=([\s\S]*?\/BannerAd))\294|sillusions\.ws[^\w.%-](?=([\s\S]*?\/vpn\-banner\.gif))\295|i\.lsimg\.net[^\w.%-](?=([\s\S]*?\/sides_clickable\.))\296|thedailyblog\.co\.nz[^\w.%-](?=([\s\S]*?_Advert_))\297|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?\/sbt\.gif))\298|eteknix\.com\/wp\-content\/uploads\/(?=([\s\S]*?Takeover))\299|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/728_))\300|dailyblogtips\.com\/wp\-content\/uploads\/(?=([\s\S]*?\.gif))\301|sfstatic\.com[^\w.%-](?=([\s\S]*?\/js\/fl\.js))\302|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-180x350\.))\303|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/180x350\.))\304|digitaltveurope\.net\/wp\-content\/uploads\/(?=([\s\S]*?_wallpaper_))\305|lego\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\306|srwww1\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\307|947\.co\.za[^\w.%-](?=([\s\S]*?\-branding\.))\308|allmovie\.com[^\w.%-](?=([\s\S]*?\/affiliate_))\309|tigerdirect\.com[^\w.%-](?=([\s\S]*?\/affiliate_))\310|islamicity\.org[^\w.%-](?=([\s\S]*?\/sponsorship\-))\311|talktalk\.co\.uk[^\w.%-](?=([\s\S]*?\/log\.html))\312|zombiegamer\.co\.za\/wp\-content\/uploads\/(?=([\s\S]*?\-skin\-))\313|rapidfiledownload\.com[^\w.%-](?=([\s\S]*?\/btn\-input\-download\.png))\314|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/billpayhelp2\.png))\315|ebaystatic\.com[^\w.%-](?=([\s\S]*?\/motorswidgetsv2\.swf))\316|hulkshare\.oncdn\.com[^\w.%-](?=([\s\S]*?\/removeads\.))\317|videoly\.co[^\w.%-](?=([\s\S]*?\/event\/))\318|xrad\.io[^\w.%-](?=([\s\S]*?\/hotspots\/))\319|llnwd\.net\/o28\/assets\/(?=([\s\S]*?\-sponsored\-))\320|dada\.net[^\w.%-](?=([\s\S]*?\/nedstat_sitestat\.js))\321|justsomething\.co\/wp\-content\/uploads\/(?=([\s\S]*?\-250x250\.))\322|hollyscoop\.com\/sites\/(?=([\s\S]*?\/skins\/))\323|dailyherald\.com[^\w.%-](?=([\s\S]*?\/contextual\.js))\324|mmoculture\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-background\-))\325|spotify\.com[^\w.%-](?=([\s\S]*?\/metric))\326|agendize\.com[^\w.%-](?=([\s\S]*?\/counts\.jsp))\327|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/ccn\.png))\328|allposters\.com[^\w.%-](?=([\s\S]*?\/banners\/))\329|guns\.ru[^\w.%-](?=([\s\S]*?\/banners\/))\330|between\-legs\.com[^\w.%-](?=([\s\S]*?\/banners\/))\331|edgecastcdn\.net[^\w.%-](?=([\s\S]*?\.barstoolsports\.com\/wp\-content\/banners\/))\332|wired\.com\/images\/xrail\/(?=([\s\S]*?\/samsung_layar_))\333|galatta\.com[^\w.%-](?=([\s\S]*?\/banners\/))\334|bizrate\.com[^\w.%-](?=([\s\S]*?\/survey_))\335|atlantafalcons\.com\/wp\-content\/(?=([\s\S]*?\/metrics\.js))\336|themittani\.com\/sites\/(?=([\s\S]*?\-skin))\337|vertical\-n\.de\/scripts\/(?=([\s\S]*?\/immer_oben\.js))\338|verticalnetwork\.de\/scripts\/(?=([\s\S]*?\/immer_oben\.js))\339|nature\.com[^\w.%-](?=([\s\S]*?\/marker\-file\.nocache))\340|mofomedia\.nl\/pop\-(?=([\s\S]*?\.js))\341|jdownloader\.org[^\w.%-](?=([\s\S]*?\/smbanner\.png))\342|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/helix\.gif))\343|kvcr\.org[^\w.%-](?=([\s\S]*?\/sponsors\/))\344|star883\.org[^\w.%-](?=([\s\S]*?\/sponsors\.))\345|freecycle\.org[^\w.%-](?=([\s\S]*?\/sponsors\/))\346|tv3\.ie[^\w.%-](?=([\s\S]*?\/sponsor\.))\347|googlesyndication\.com[^\w.%-](?=([\s\S]*?\/click_to_buy\/))\348|bassmaster\.com[^\w.%-](?=([\s\S]*?\/premier_sponsor_logo\/))\349|upickem\.net[^\w.%-](?=([\s\S]*?\/affiliates\/))\350|hwscdn\.com[^\w.%-](?=([\s\S]*?\/brands_analytics\.js))\351|totallylayouts\.com[^\w.%-](?=([\s\S]*?\/visitor\-counter\/counter\.js))\352|adprimemedia\.com[^\w.%-](?=([\s\S]*?\/video_report\/videoReport\.php))\353|adprimemedia\.com[^\w.%-](?=([\s\S]*?\/video_report\/attemptAdReport\.php))\354|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?_270x312\.))\355|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?_1170x120\.))\356|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/7281\.gif))\357|madamenoire\.com\/wp\-content\/(?=([\s\S]*?_Reskin\-))\358|kexp\.org[^\w.%-](?=([\s\S]*?\/sponsoredby\.))\359|celebstoner\.com\/assets\/images\/img\/sidebar\/(?=([\s\S]*?\/freedomleaf\.png))\360|nbr\.co\.nz[^\w.%-](?=([\s\S]*?\-WingBanner_))\361|dnsstuff\.com\/dnsmedia\/images\/(?=([\s\S]*?_banner\.jpg))\362|aolcdn\.com\/os\/music\/img\/(?=([\s\S]*?\-skin\.jpg))\363|xxxgames\.biz[^\w.%-](?=([\s\S]*?\/sponsors\/))\364|thessdreview\.com[^\w.%-](?=([\s\S]*?\/owc\-full\-banner\.jpg))\365|armorgames\.com[^\w.%-](?=([\s\S]*?\/siteskin\.css))\366|amazonaws\.com[^\w.%-](?=([\s\S]*?\/player_request_))\367(?=([\s\S]*?\/get_affiliate_))\368|samoatimes\.co\.nz[^\w.%-](?=([\s\S]*?\/banner468x60\/))\369|thessdreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/930x64_))\370|pbs\.org[^\w.%-](?=([\s\S]*?\/sponsors\/))\371|dreamscene\.org[^\w.%-](?=([\s\S]*?_Banner\.))\372|mrskincdn\.com[^\w.%-](?=([\s\S]*?\/flash\/aff\/))\373|punch\.cdn\.ng[^\w.%-](?=([\s\S]*?\/wp\-banners\/))\374|dell\.com\/images\/global\/js\/s_metrics(?=([\s\S]*?\.js))\375|yimg\.com\/cv\/(?=([\s\S]*?\/config\-object\-html5billboardfloatexp\.js))\376|nzpages\.co\.nz[^\w.%-](?=([\s\S]*?\/banners\/))\377|amazon\.(?=([\s\S]*?\/ajax\/counter))\378|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-vertical\.))\379|amazon\.(?=([\s\S]*?\/gp\/r\.html))\380)/i;
var bad_da_hostpath_regex_flag = 939 > 0 ? true : false;  // test for non-zero number of rules
    
// 176 rules as an efficient NFA RegExp:
var bad_da_RegExp = /^(?:[\w-]+\.)*?(?:porntube\.com\/ads$|ads\.|adv\.|1337x\.to[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|banner\.|banners\.|torrentz2\.eu[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|affiliate\.|affiliates\.|cloudfront\.net\/\?a=|erotikdeal\.com\/\?ref=|quantserve\.com\/pixel;|synad\.|cursecdn\.com\/shared\-assets\/current\/anchor\.js\?id=|yahoo\.com\/p\.gif;|bluehost\.com\/web\-hosting\/domaincheckapi\/\?affiliate=|kickass2\.st[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|cloudfront\.net\/\?tid=|oddschecker\.com\/clickout\.htm\?type=takeover\-|bittorrent\.am[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|katcr\.co[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|sweed\.to\/\?pid=|nowwatchtvlive\.ws[^\w.%-]\$csp=script\-src 'self' |qualtrics\.com\/WRSiteInterceptEngine\/\?Q_Impress=|x1337x\.ws[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|torrentdownloads\.me[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|uploadproper\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|tube911\.com\/scj\/cgi\/out\.php\?scheme_id=|watchsomuch\.info[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|movies\.askjolene\.com\/c64\?clickid=|ipornia\.com\/scj\/cgi\/out\.php\?scheme_id=|torrentdownload\.ch[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|torrentfunk2\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|pirateiro\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|magnetdl\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|yourbittorrent2\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|limetorrents\.info[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|api\.ticketnetwork\.com\/Events\/TopSelling\/domain=nytimes\.com|consensu\.org\/\?log=|totalporn\.com\/videos\/tracking\/\?url=|ad\.atdmt\.com\/i\/go;|t\-online\.de[^\w.%-](?=([\s\S]*?\/stats\.js\?track=))\1|tinypic\.com\/api\.php\?(?=([\s\S]*?&action=track))\2|fantasti\.cc[^\w.%-](?=([\s\S]*?\?ad=))\3|casino\-x\.com[^\w.%-](?=([\s\S]*?\?partner=))\4|allmyvideos\.net\/(?=([\s\S]*?=))\5|quantserve\.com[^\w.%-](?=([\s\S]*?[^\w.%-]a=))\6|exashare\.com[^\w.%-](?=([\s\S]*?&h=))\7|blacklistednews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\8|swatchseries\.to[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\9|acidcow\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\10|ad\.atdmt\.com\/i\/(?=([\s\S]*?=))\11|thevideo\.me\/(?=([\s\S]*?\:))\12|1movies\.is[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' 'unsafe\-eval' data\: (?=([\s\S]*?\.jwpcdn\.com ))\13(?=([\s\S]*?\.gstatic\.com ))\14(?=([\s\S]*?\.googletagmanager\.com ))\15(?=([\s\S]*?\.addthis\.com ))\16(?=([\s\S]*?\.google\.com))\17|phonearena\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\18|uptobox\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline' ))\19(?=([\s\S]*?\.gstatic\.com ))\20(?=([\s\S]*?\.google\.com ))\21(?=([\s\S]*?\.googleapis\.com))\22|iyfsearch\.com[^\w.%-](?=([\s\S]*?&pid=))\23|2hot4fb\.com\/img\/(?=([\s\S]*?\.gif\?r=))\24|watchcartoononline\.io[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\25|merriam\-webster\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\26|flirt4free\.com[^\w.%-](?=([\s\S]*?&utm_campaign))\27|pornsharing\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' 'unsafe\-eval' data\: (?=([\s\S]*?\.google\.com ))\28(?=([\s\S]*?\.gstatic\.com ))\29(?=([\s\S]*?\.google\-analytics\.com))\30|plista\.com\/widgetdata\.php\?(?=([\s\S]*?%22pictureads%22%7D))\31|wikia\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline' 'unsafe\-eval' ))\32(?=([\s\S]*?\.jwpsrv\.com ))\33(?=([\s\S]*?\.jwplayer\.com))\34|shortcuts\.search\.yahoo\.com[^\w.%-](?=([\s\S]*?&callback=yahoo\.shortcuts\.utils\.setdittoadcontents&))\35|media\.campartner\.com\/index\.php\?cpID=(?=([\s\S]*?&cpMID=))\36|postimg\.cc\/image\/\$csp=script\-src 'self' (?=([\s\S]*? data\: blob\: 'unsafe\-eval'))\37|sobusygirls\.fr[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-eval'))\38|unblocked\.win[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\39|videogamesblogger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\40(?=([\s\S]*?\.gstatic\.com ))\41(?=([\s\S]*?\.google\.com ))\42(?=([\s\S]*?\.googleapis\.com ))\43(?=([\s\S]*?\.playwire\.com ))\44(?=([\s\S]*?\.facebook\.com ))\45(?=([\s\S]*?\.bootstrapcdn\.com ))\46(?=([\s\S]*?\.twitter\.com ))\47(?=([\s\S]*?\.spot\.im))\48|get\.(?=([\s\S]*?\.website\/static\/get\-js\?stid=))\49|bighealthreport\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\50(?=([\s\S]*?\.gstatic\.com ))\51(?=([\s\S]*?\.google\.com ))\52(?=([\s\S]*?\.googleapis\.com ))\53(?=([\s\S]*?\.playwire\.com ))\54(?=([\s\S]*?\.facebook\.com ))\55(?=([\s\S]*?\.bootstrapcdn\.com ))\56(?=([\s\S]*?\.yimg\.com))\57|btkitty\.pet[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' (?=([\s\S]*?\.cloudflare\.com ))\58(?=([\s\S]*?\.googleapis\.com ))\59(?=([\s\S]*?\.jsdelivr\.net))\60|eafyfsuh\.net[^\w.%-](?=([\s\S]*?\/\?name=))\61|pockettactics\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\62|linkbucks\.com[^\w.%-](?=([\s\S]*?\/\?))\63(?=([\s\S]*?=))\64|lijit\.com\/blog_wijits\?(?=([\s\S]*?=trakr&))\65|freehostedscripts\.net[^\w.%-](?=([\s\S]*?\.php\?site=))\66(?=([\s\S]*?&s=))\67(?=([\s\S]*?&h=))\68|facebook\.com\/(?=([\s\S]*?\/plugins\/send_to_messenger\.php\?app_id=))\69|answerology\.com\/index\.aspx\?(?=([\s\S]*?=ads\.ascx))\70|doubleclick\.net\/pfadx\/(?=([\s\S]*?adcat=))\71|ifly\.com\/trip\-plan\/ifly\-trip\?(?=([\s\S]*?&ad=))\72|freebeacon\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\73|torrentz\.eu\/search(?=([\s\S]*?=))\74|solarmovie\.one[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\75|viralnova\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\76(?=([\s\S]*?\.gstatic\.com ))\77(?=([\s\S]*?\.google\.com ))\78(?=([\s\S]*?\.googleapis\.com ))\79(?=([\s\S]*?\.playwire\.com ))\80(?=([\s\S]*?\.facebook\.com ))\81(?=([\s\S]*?\.bootstrapcdn\.com))\82|barbwire\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\83(?=([\s\S]*?\.gstatic\.com ))\84(?=([\s\S]*?\.google\.com ))\85(?=([\s\S]*?\.googleapis\.com ))\86(?=([\s\S]*?\.playwire\.com ))\87(?=([\s\S]*?\.facebook\.com ))\88(?=([\s\S]*?\.bootstrapcdn\.com))\89|thehayride\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\90(?=([\s\S]*?\.gstatic\.com ))\91(?=([\s\S]*?\.google\.com ))\92(?=([\s\S]*?\.googleapis\.com ))\93(?=([\s\S]*?\.playwire\.com ))\94(?=([\s\S]*?\.facebook\.com ))\95(?=([\s\S]*?\.bootstrapcdn\.com))\96|wakingtimes\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\97(?=([\s\S]*?\.gstatic\.com ))\98(?=([\s\S]*?\.google\.com ))\99(?=([\s\S]*?\.googleapis\.com ))\100(?=([\s\S]*?\.playwire\.com ))\101(?=([\s\S]*?\.facebook\.com ))\102(?=([\s\S]*?\.bootstrapcdn\.com))\103|activistpost\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\104(?=([\s\S]*?\.gstatic\.com ))\105(?=([\s\S]*?\.google\.com ))\106(?=([\s\S]*?\.googleapis\.com ))\107(?=([\s\S]*?\.playwire\.com ))\108(?=([\s\S]*?\.facebook\.com ))\109(?=([\s\S]*?\.bootstrapcdn\.com))\110|allthingsvegas\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\111(?=([\s\S]*?\.gstatic\.com ))\112(?=([\s\S]*?\.google\.com ))\113(?=([\s\S]*?\.googleapis\.com ))\114(?=([\s\S]*?\.playwire\.com ))\115(?=([\s\S]*?\.facebook\.com ))\116(?=([\s\S]*?\.bootstrapcdn\.com))\117|survivalnation\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\118(?=([\s\S]*?\.gstatic\.com ))\119(?=([\s\S]*?\.google\.com ))\120(?=([\s\S]*?\.googleapis\.com ))\121(?=([\s\S]*?\.playwire\.com ))\122(?=([\s\S]*?\.facebook\.com ))\123(?=([\s\S]*?\.bootstrapcdn\.com))\124|thelibertydaily\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\125(?=([\s\S]*?\.gstatic\.com ))\126(?=([\s\S]*?\.google\.com ))\127(?=([\s\S]*?\.googleapis\.com ))\128(?=([\s\S]*?\.playwire\.com ))\129(?=([\s\S]*?\.facebook\.com ))\130(?=([\s\S]*?\.bootstrapcdn\.com))\131|visiontoamerica\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\132(?=([\s\S]*?\.gstatic\.com ))\133(?=([\s\S]*?\.google\.com ))\134(?=([\s\S]*?\.googleapis\.com ))\135(?=([\s\S]*?\.playwire\.com ))\136(?=([\s\S]*?\.facebook\.com ))\137(?=([\s\S]*?\.bootstrapcdn\.com))\138|comicallyincorrect\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\139(?=([\s\S]*?\.gstatic\.com ))\140(?=([\s\S]*?\.google\.com ))\141(?=([\s\S]*?\.googleapis\.com ))\142(?=([\s\S]*?\.playwire\.com ))\143(?=([\s\S]*?\.facebook\.com ))\144(?=([\s\S]*?\.bootstrapcdn\.com))\145|americasfreedomfighters\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\146(?=([\s\S]*?\.gstatic\.com ))\147(?=([\s\S]*?\.google\.com ))\148(?=([\s\S]*?\.googleapis\.com ))\149(?=([\s\S]*?\.playwire\.com ))\150(?=([\s\S]*?\.facebook\.com ))\151(?=([\s\S]*?\.bootstrapcdn\.com))\152|bulletsfirst\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\153(?=([\s\S]*?\.gstatic\.com ))\154(?=([\s\S]*?\.google\.com ))\155(?=([\s\S]*?\.googleapis\.com ))\156(?=([\s\S]*?\.playwire\.com ))\157(?=([\s\S]*?\.facebook\.com ))\158(?=([\s\S]*?\.bootstrapcdn\.com))\159|rover\.ebay\.com\.au[^\w.%-](?=([\s\S]*?&cguid=))\160|waybig\.com\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\?pas=))\161|shopify\.com\/(?=([\s\S]*?\/page\?))\162(?=([\s\S]*?&eventType=))\163|extremetech\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\164|tipico\.(?=([\s\S]*?\?affiliateId=))\165|yifyddl\.movie[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' (?=([\s\S]*?\.googleapis\.com))\166|moviewatcher\.is[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\167|tipico\.com[^\w.%-](?=([\s\S]*?\?affiliateid=))\168|123unblock\.xyz[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\169|unblocked\.pet[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\170|machinenoveltranslation\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\171|fullmatchesandshows\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\172|nintendoeverything\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\173|textsfromlastnight\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\174|powerofpositivity\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\175|talkwithstranger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\176|readliverpoolfc\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\177|androidcentral\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\178|roadracerunner\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\179|tetrisfriends\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\180|thisisfutbol\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\181|almasdarnews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\182|colourlovers\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\183|convertfiles\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\184|investopedia\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\185|skidrowcrack\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\186|sportspickle\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\187|hiphopearly\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\188|readarsenal\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\189|kshowonline\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\190|moneyversed\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\191|thehornnews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\192|torrentfunk\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\193|videocelts\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\194|britannica\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\195|csgolounge\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\196|grammarist\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\197|healthline\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\198|tworeddots\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\199|wuxiaworld\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\200|kiplinger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\201|readmng\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\202|trifind\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\203|vidmax\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\204|debka\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\205|onion\.ly[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\206|prox4you\.pw[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\207|hop\.clickbank\.net\/(?=([\s\S]*?&transaction_id=))\208(?=([\s\S]*?&offer_id=))\209|computerarts\.co\.uk\/(?=([\s\S]*?\.php\?cmd=site\-stats))\210|unblockall\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\211|biology\-online\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\212|ancient\-origins\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\213|asheepnomore\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\214|campussports\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\215|toptenz\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\216|skyscanner\.(?=([\s\S]*?\/slipstream\/applog$))\217|blog\-rct\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\218|lolcounter\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\219|nsfwyoutube\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\220|thecelticblog\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\221|winit\.winchristmas\.co\.uk[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\222|videolike\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\223|broadwayworld\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\224|unblocked\.si[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\225|amazon\.com\/gp\/(?=([\s\S]*?&linkCode))\226|convertcase\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\227|daclips\.in[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\228|newser\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\229|nocensor\.pro[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\230|unlockproject\.icu[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\231|mrunlock\.icu[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\232|menrec\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\233(?=([\s\S]*?\.google\.com ))\234(?=([\s\S]*?\.googleapis\.com ))\235(?=([\s\S]*?\.facebook\.com ))\236(?=([\s\S]*?\.bootstrapcdn\.com ))\237(?=([\s\S]*?\.twitter\.com ))\238(?=([\s\S]*?\.spot\.im))\239|ipatriot\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\240(?=([\s\S]*?\.google\.com ))\241(?=([\s\S]*?\.googleapis\.com ))\242(?=([\s\S]*?\.facebook\.com ))\243(?=([\s\S]*?\.bootstrapcdn\.com ))\244(?=([\s\S]*?\.twitter\.com ))\245(?=([\s\S]*?\.spot\.im))\246|clashdaily\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\247(?=([\s\S]*?\.google\.com ))\248(?=([\s\S]*?\.googleapis\.com ))\249(?=([\s\S]*?\.facebook\.com ))\250(?=([\s\S]*?\.bootstrapcdn\.com ))\251(?=([\s\S]*?\.twitter\.com ))\252(?=([\s\S]*?\.spot\.im))\253|dcdirtylaundry\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\254(?=([\s\S]*?\.google\.com ))\255(?=([\s\S]*?\.googleapis\.com ))\256(?=([\s\S]*?\.facebook\.com ))\257(?=([\s\S]*?\.bootstrapcdn\.com ))\258(?=([\s\S]*?\.twitter\.com ))\259(?=([\s\S]*?\.spot\.im))\260|thinkamericana\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\261(?=([\s\S]*?\.google\.com ))\262(?=([\s\S]*?\.googleapis\.com ))\263(?=([\s\S]*?\.facebook\.com ))\264(?=([\s\S]*?\.bootstrapcdn\.com ))\265(?=([\s\S]*?\.twitter\.com ))\266(?=([\s\S]*?\.spot\.im))\267|godfatherpolitics\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\268(?=([\s\S]*?\.google\.com ))\269(?=([\s\S]*?\.googleapis\.com ))\270(?=([\s\S]*?\.facebook\.com ))\271(?=([\s\S]*?\.bootstrapcdn\.com ))\272(?=([\s\S]*?\.twitter\.com ))\273(?=([\s\S]*?\.spot\.im))\274|libertyunyielding\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\275(?=([\s\S]*?\.google\.com ))\276(?=([\s\S]*?\.googleapis\.com ))\277(?=([\s\S]*?\.facebook\.com ))\278(?=([\s\S]*?\.bootstrapcdn\.com ))\279(?=([\s\S]*?\.twitter\.com ))\280(?=([\s\S]*?\.spot\.im))\281|conservativefiringline\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\282(?=([\s\S]*?\.google\.com ))\283(?=([\s\S]*?\.googleapis\.com ))\284(?=([\s\S]*?\.facebook\.com ))\285(?=([\s\S]*?\.bootstrapcdn\.com ))\286(?=([\s\S]*?\.twitter\.com ))\287(?=([\s\S]*?\.spot\.im))\288)/i;
var bad_da_regex_flag = 176 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_url_parts_RegExp = /^$/;
var good_url_parts_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 2579 rules as an efficient NFA RegExp:
var bad_url_parts_RegExp = /(?:\/adcontent\.|\/adsys\/|\/adserver\.|\/pp\-ad\.|\.com\/ads\?|\?getad=&|\/img\/adv\.|\/img\/adv\/|\/expandable_ad\?|\.online\/ads\/|\/online\/ads\/|\/online\-ad_|_online_ad\.|\/ad\-engine\.|\/ad_engine\?|\/homepage\-ads\/|\/homepage\/ads\/|\-online\-advert\.|\-web\-ad\-|\/web\-ad_|\/imgad\.|\/imgad\?|\/iframead\.|\/iframead\/|\/contentad\/|\/contentad$|\-leaderboard\-ad\-|\/leaderboard_ad\.|\/leaderboard_ad\/|\-ad\-content\/|\/ad\/content\/|\/ad_content\.|\/adcontent\/|\/ad\-images\/|\/ad\/images\/|\/ad_images\/|\/static\/tracking\/|\/ad\-image\.|\/ad\/image\/|\/ad_image\.|\/webad\?|_webad\.|\/adplugin\.|\/adplugin\/|\/adplugin_|\-content\-ad\-|\-content\-ad\.|\/content\/ad\/|\/content\/ad_|\/content_ad\.|_content_ad\.|\/video\-ad\.|\/video\/ad\/|\/video_ad\.|\-iframe\-ad\.|\/iframe\-ad\.|\/iframe\-ad\/|\/iframe\-ad\?|\/iframe\.ad\/|\/iframe\/ad\/|\/iframe\/ad_|\/iframe_ad\.|\/iframe_ad\?|\.com\/video\-ad\-|\/superads_|_js\/ads\.js|\/web\-analytics\.|\/web_analytics\/|\-ad_leaderboard\/|\/ad\-leaderboard\.|\/ad\/leaderboard\.|\/ad_leaderboard\.|\/ad_leaderboard\/|=ad\-leaderboard\-|\/_img\/ad_|\/img\/_ad\.|\/img\/ad\-|\/img\/ad\.|\/img\/ad\/|\/img_ad\/|=adcenter&|\/assets\/js\/ad\.|\.adriver\.|\/adriver\.|\/adriver_|\/popad$|\.com\/\?adv=|\/t\/event\.js\?|\/pop2\.js$|\-ad\-iframe\.|\-ad\-iframe\/|\-ad\/iframe\/|\/ad\-iframe\-|\/ad\-iframe\.|\/ad\-iframe\?|\/ad\/iframe\.|\/ad\/iframe\/|\/ad\?iframe_|\/ad_iframe\.|\/ad_iframe_|=ad_iframe&|=ad_iframe_|\/xtclicks\.|\/xtclicks_|\/bottom\-ads\.|\/ad\.php$|\-text\-ads\.|_search\/ads\.js|\/post\/ads\/|\/bg\/ads\/|\/expandable_ad\.php|\-top\-ads\.|\/top\-ads\.|\.net\/ad\/|\-show\-ads\.|\/show\-ads\.|\/footer\-ads\/|\/ad132m\/|\/inc\/ads\/|\/ad_pop\.php\?|\/adclick\.|\.co\/ads\/|\-iframe\-ads\/|\/iframe\-ads\/|\/iframe\/ads\/|\-ads\-iframe\.|\/ads\/iframe|\/ads_iframe\.|\/afs\/ads\/|\/mobile\-ads\/|\/special\-ads\/|\-article\-ads\-|\-video\-ads\/|\/video\-ads\/|\/video\.ads\.|\/video\/ads\/|\/dynamic\/ads\/|\.no\/ads\/|\/modules\/ads\/|\/user\/ads\?|\/pc\/ads\.|\/ad\?count=|\/ad_count\.|\/remove\-ads\.|\/mini\-ads\/|\/js\/ads\-|\/js\/ads\.|\/js\/ads_|\/vast\/ads\-|\/i\/ads\/|\/cms\/ads\/|\/ads\.cms|\/td\-ads\-|\/player\/ads\.|\/player\/ads\/|\/ads\/html\/|\/showads\/|\/external\/ads\/|\/ext\/ads\/|\/left\-ads\.|\/ad\/logo\/|\/default\/ads\/|\/responsive\-ads\.|_track\/ad\/|\/custom\/ads|\/delivery\.ads\.|\/ads\/click\?|\/media\/ad\/|\/house\-ads\/|\/ads12\.|\/ads\/targeting\.|\-adskin\.|\/adskin\/|\/ads_reporting\/|\/adsetup\.|\/adsetup_|\/ad\?sponsor=|\/adsframe\.|\/sidebar\-ads\/|\/ads\/async\/|\/blogad\.|\/adbanners\/|\/adsdaq_|\/popupads\.|\/image\/ads\/|\/image\/ads_|\/ads\.htm|\/click\?adv=|&program=revshare&|\/click\.track\?|\.ads\.css|\/ads\.css|\/analytics\.gif\?|\/realmedia\/ads\/|\-peel\-ads\-|\/banner\-adv\-|\/banner\/adv\/|\/banner\/adv_|\/adlog\.|\/adsrv\.|\/adsrv\/|\/adsys\.|\/aff_ad\?|\/plugins\/ads\-|\/plugins\/ads\/|\/ads\.php|\/ads_php\/|\/log\/ad\-|\/log_ad\?|\/sponsored_ad\.|\/sponsored_ad\/|\/lazy\-ads\-|\/lazy\-ads\.|\.link\/ads\/|\/partner\.ads\.|\/ad_video\.htm|\/ads8\.|\/ads8\/|\/adsjs\.|\/adsjs\/|\/ads\/square\-|\/ads\/square\.|\/adstop\.|\/adstop_|\/video\-ad\-overlay\.|\/new\-ads\/|\/new\/ads\/|\.ads1\-|\.ads1\.|\/ads1\.|\/ads1\/|&adcount=|\-adbanner\.|\.adbanner\.|\/adbanner\.|\/adbanner\/|\/adbanner_|=adbanner_|\/ads\.js\.|\/ads\.js\/|\/ads\.js\?|\/ads\/js\.|\/ads\/js\/|\/ads\/js_|\/adpartner\.|\?adpartner=|\/google_tag\.|\/google_tag\/|\/ads\/text\/|\/ads_text_|\/s_ad\.aspx\?|\/adClick\/|\/adClick\?|\/blog\/ads\/|\-adsonar\.|\/adsonar\.|\/flash\-ads\.|\/flash\-ads\/|\/flash\/ads\/|=popunders&|\/home\/ads\-|\/home\/ads\/|\/home\/ads_|\.ads9\.|\/ads9\.|\/ads9\/|\.adserve\.|\/adserve\-|\/adserve\.|\/adserve\/|\/adserve_|&popunder=|\/popunder\.|\/popunder_|=popunder&|_popunder\+|\-adsystem\-|\/adsystem\.|\/adsystem\/|\/bannerad\.|\/bannerad\/|_bannerad\.|\/ads\-new\.|\/ads_new\.|\/ads_new\/|\/ad\.html\?|\/ad\/html\/|\/ad_html\/|\/ad\/js\/pushdown\.|&adspace=|\-adspace\.|\-adspace_|\.adspace\.|\/adspace\.|\/adspace\/|\/adspace\?|\-banner\-ads\-|\-banner\-ads\/|\/banner\-ads\-|\/banner\-ads\/|\.ads3\-|\/ads3\.|\/ads3\/|\.adsense\.|\/adsense\-|\/adsense\/|\/adsense\?|;adsense_|\/bin\/stats\?|\/ads\-top\.|\/ads\/top\-|\/ads\/top\.|\/ads_top_|\/a\-ads\.|\/ads\/index\-|\/ads\/index\.|\/ads\/index\/|\/ads\/index_|\-dfp\-ads\/|\/dfp\-ads\.|\/dfp\-ads\/|\/web\-ads\.|\/web\-ads\/|\/web\/ads\/|=web&ads=|\-img\/ads\/|\/img\-ads\.|\/img\-ads\/|\/img\.ads\.|\/img\/ads\/|\/site\-ads\/|\/site\/ads\/|\/site\/ads\?|\/adstat\.|\.ads2\-|\/ads2\.|\/ads2\/|\/ads2_|\-adscript\.|\/adscript\.|\/adscript\?|\/adscript_|\.com\/counter\?|_mobile\/js\/ad\.|\/admanager\/|\-search\-ads\.|\/search\-ads\?|\/search\/ads\?|\/search\/ads_|\/adb_script\/|\/google\/adv\.|\/assets\/sponsored\/|\/images\.ads\.|\/images\/ads\-|\/images\/ads\.|\/images\/ads\/|\/images\/ads_|_images\/ads\/|&adserver=|\-adserver\-|\-adserver\.|\-adserver\/|\.adserver\.|\/adserver\-|\/adserver\/|\/adserver\?|\/adserver_|\/adshow\-|\/adshow\.|\/adshow\/|\/adshow\?|\/adshow_|=adshow&|\/media\/ads\/|_media\/ads\/|\/ajax\/track\.php\?|\/plugins\/ad\.|\/static\/ads\/|_static\/ads\/|\-google\-ads\-|\-google\-ads\/|\/google\-ads\.|\/google\-ads\/|\-ad\-banner\-|\-ad\-banner\.|\-ad_banner\-|\/ad\-banner\-|\/ad\-banner\.|\/ad\/banner\.|\/ad\/banner\/|\/ad\/banner\?|\/ad\/banner_|\/ad_banner\.|\/ad_banner\/|\/ad_banner_|\-banner\-ad\-|\-banner\-ad\.|\-banner\-ad\/|\/banner\-ad\-|\/banner\-ad\.|\/banner\-ad\/|\/banner\-ad_|\/banner\/ad\.|\/banner\/ad\/|\/banner\/ad_|\/banner_ad\.|_banner\-ad\.|_banner_ad\-|_banner_ad\.|_banner_ad\/|\/product\-ad\/|\/pages\/ads|\/adpreview\?|\/videoad\.|_videoad\.|\/advlink\.|\.com\/js\/ads\/|\/tracker\/tracker\.js|\/googlead\-|\/googlead\.|_googlead\.|\?AdUrl=|\/js\/_analytics\/|\/js\/analytics\.|\/goad$|\/ads\/popshow\.|\/my\-ad\-injector\/|&advertiserid=|\.net\/adx\.php\?|\.com\/stats\.ashx\?|\-images\/ad\-|\/images\-ad\/|\/images\/ad\-|\/images\/ad\/|\/images_ad\/|_images\/ad\.|_images\/ad_|\/adworks\/|\/userad\/|\.com\/ads\-|\.com\/ads\.|\.com\/ads_|\/com\/ads\/|_mainad\.|\/admax\/|=advertiser\.|=advertiser\/|\?advertiser=|_WebAd[^\w.%-]|\/adblocker\/pixel\.|\/ad\-minister\-|\/video\-ads\-management\.|\-ad0\.|\/ga_social_tracking_|\/embed\-log\.js|_ad\.png\?|\/video\-ads\-player\.|\/public\/js\/ad\/|\/adwords\/|\/ad\-manager\/|\/ad_manager\.|\/ad_manager\/|\/adfactory\-|\/adfactory_|\/adplayer\-|\/adplayer\/|\.com\/im\-ad\/|\.com\/im_ad\/|\-adops\.|\/adops\/|\/adimg\/|\/js\/oas\-|\/js\/oas\.|\.com\/\?ad=|\.com\/ad\?|\/ads\/ads\.|\/ads\/ads\/|\/ads\/ads_|=adlabs&|\-google\-ad\.|\/google\-ad\-|\/google\-ad\?|\/google\/ad\?|\/google_ad\.|_google_ad\.|\/adlink\?|\/adlink_|\/ajax\-track\-view\.|\/adseo\/|\/adsterra\/|\-advertising\/assets\/|\/images\/adver\-|\-advt\.|\/advt\/|\/ad\.css\?|\/\?advideo\/|\?advideo_|\/analytics\-v1\.|\/tracking\/track\.php\?|\-ad\-pixel\-|\/\?addyn$|\/admedia\/|_smartads_|\/socialads\/|\/tracker\/track\.php\?|\/track\/track\.php\?|\.ads4\-|\/ads4\/|\-adman\/|\/adman\/|\/adman_|\/campaign\/advertiser_|\/flashads\/|\/wp\-content\/ads\/|\/images\/ad2\/|\/utep_ad\.js|\/adbroker\.|\/adbroker\/|\-adtrack\.|\/adtrack\/|\/_\/ads\/|\/pop_ad\.|_pop_ad\.|_pop_ad\/|\/amp\-ad\-|\/advertisments\/|\/sensorsdata\-|\/adnow\-|\/g_track\.php\?|\.net\/ads\-|\.net\/ads\.|\.net\/ads\/|\.net\/ads\?|\.net\/ads_|\-image\-ad\.|\/image\/ad\/|\/adblock\-img\.|\/img\-advert\-|&adurl=|\?adx=|\/chartbeat\.js|_chartbeat\.js|\/admaster\?|\/adservice\-|\/adservice\/|\/adservice$|\/adblock_alerter\.|\/adblock\-alerter\/|\/ajax\/optimizely\-|\/ero\-advertising\.|\/adx\/iframe\.|\/adx_iframe_|\.core\.tracking\-min\-|\/show\-ad\.|\/show\.ad\?|\/show_ad\.|\/show_ad\?|\?affiliate=|\/intelliad\.|\/leaderboard\-advert\.|\/adv\-expand\/|&adnet=|\/pixel\/js\/|\/getad\/|\/getad\?|\/adiframe\.|\/adiframe\/|\/adiframe\?|\/adiframe_|\/adrolays\.|\-adspot\-|\/adspot\/|\/adspot_|\?adspot_|_doubleclick\.|\/exoclick$|\/googleads\-|\/googleads\/|\/googleads_|_googleads_|\/adhandler\.|\/adimages\.|\/nuggad\.|\/nuggad\/|\/analytics\/track\-|\/analytics\/track\.|\/analytics\/track\/|\/analytics\/track\?|\/analytics\/track$|\/adguru\.|\/ad_pop\.|\/adcash\-|\/adcash$|\/iframes\/ad\/|\/cpx\-advert\/|\/adfox\/|\?adfox_|\/adverthorisontalfullwidth\.|\.AdmPixelsCacheController\?|\/adaptvexchangevastvideo\.|\/ForumViewTopicContentAD\.|\/postprofilehorizontalad\.|=adreplacementWrapperReg\.|\.net\/ad2\/|\/adClosefeedbackUpgrade\.|\/adzonecenteradhomepage\.|\/ForumViewTopicBottomAD\.|\/advertisementrotation\.|\/advertisingimageexte\/|\/AdvertisingIsPresent6\?|\/postprofileverticalad\.|\/adblockdetectorwithga\.|\/admanagementadvanced\.|\/advertisementmapping\.|\/initlayeredwelcomead\-|\/advertisementheader\.|\/advertisingcontent\/|\/advertisingwidgets\/|\/thirdpartyframedad\/|\.AdvertismentBottom\.|\/adfrequencycapping\.|\/adgearsegmentation\.|\/advertisementview\/|\/advertising300x250\.|\/advertverticallong\.|\/AdZonePlayerRight2\.|\/ShowInterstitialAd\.|\/adwizard\.|\/adwizard\/|\/adwizard_|\/addeliverymodule\/|\/adinsertionplugin\.|\/AdPostInjectAsync\.|\/adrendererfactory\.|\/advertguruonline1\.|\/advertisementAPI\/|\/advertisingbutton\.|\/advertisingmanual\.|\/advertisingmodule\.|\/adzonebelowplayer\.|\/adzoneplayerright\.|\/jumpstartunpaidad\.|\?adtechplacementid=|\/adasiatagmanager\.|\/adforgame160x600\.|\/adframe728homebh\.|\/adleaderboardtop\.|\/adpositionsizein\-|\/adreplace160x600\.|\/advertise125x125\.|\/advertisement160\.|\/advertiserwidget\.|\/advertisinglinks_|\/advFrameCollapse\.|\/requestmyspacead\.|\/supernorthroomad\.|\/adblockdetection\.|\/adBlockDetector\/|\.advertrecycling\.|\/adbriteincleft2\.|\/adbriteincright\.|\/adchoicesfooter\.|\/adgalleryheader\.|\/adindicatortext\.|\/admatcherclient\.|\/adoverlayplugin\.|\/adreplace728x90\.|\/adtaggingsubsec\.|\/adtagtranslator\.|\/adultadworldpop_|\/advertisements2\.|\/advertisewithus_|\/adWiseShopPlus1\.|\/adwrapperiframe\.|\/contentmobilead\.|\/convertjsontoad\.|\/HompageStickyAd\.|\/mobilephonesad\/|\/sample300x250ad\.|\/tomorrowfocusAd\.|\/adforgame728x90\.|\/adforgame728x90_|\/AdblockMessage\.|\/AdAppSettings\/|\/adinteraction\/|\/adaptvadplayer\.|\/adcalloverride\.|\/adfeedtestview\.|\/adframe120x240\.|\/adframewrapper\.|\/adiframeanchor\.|\/adlantisloader\.|\/adlargefooter2\.|\/adpanelcontent\.|\/adverfisement2\.|\/advertisement1\.|\/advertisement2\.|\/advertisement3\.|\/dynamicvideoad\?|\/premierebtnad\/|\/rotatingtextad\.|\/sample728x90ad\.|\/slideshowintad\?|\/adblockchecker\.|\/adblockdetect\.|\/adblockdetect\/|\/google\-analytics\-|\/google\-analytics\.|\/google\/analytics_|\/google_analytics\.|\-advertising11\.|\/adchoicesicon\.|\/adframe728bot\.|\/adframebottom\.|\/adframecommon\.|\/adframemiddle\.|\/adinsertjuicy\.|\/adlargefooter\.|\/adleftsidebar\.|\/admanagement\/|\/adMarketplace\.|\/admentorserve\.|\/adotubeplugin\.|\/adPlaceholder\.|\/advaluewriter\.|\/adverfisement\.|\/advertbuttons_|\/advertising02\.|\/advertisment1\-|\/advertisment4\.|\/bottomsidead\/|\/getdigitalad\/|\/gigyatargetad\.|\/gutterspacead\.|\/leaderboardad\.|\/newrightcolad\.|\/promobuttonad\.|\/rawtubelivead\.|\/restorationad\-|=admodeliframe&|\/adblockkiller\.|\-web\-advert\-|_web\-advert\.|\/addpageview\/|\/admonitoring\.|&customSizeAd=|\-printhousead\-|\.advertmarket\.|\/AdBackground\.|\/adcampaigns\/|\/adcomponent\/|\/adcontroller\.|\/adfootcenter\.|\/adframe728b2\.|\/adifyoverlay\.|\/admeldscript\.|\/admentor302\/|\/admentorasp\/|\/adnetwork300\.|\/adnetwork468\.|\/AdNewsclip14\.|\/AdNewsclip15\.|\/adoptionicon\.|\/adrequisitor\-|\/adTagRequest\.|\/adtechHeader\.|\/adtechscript\.|\/adTemplates\/|\/advertisings\.|\/advertsquare\.|\/advertwebapp\.|\/advolatility\.|\/adzonebottom\.|\/adzonelegend\.|\/brightcovead\.|\/contextualad\.|\/custom11x5ad\.|\/horizontalAd\.|\/iframedartad\.|\/indexwaterad\.|\/jsVideoPopAd\.|\/PageBottomAD\.|\/skyscraperad\.|\/writelayerad\.|=dynamicwebad&|\-advertising2\-|\/advertising2\.|\/advtemplate\/|\/advtemplate_|\/adimppixel\/|\-adcompanion\.|\-adtechfront\.|\-advertise01\.|\-rightrailad\-|\.xinhuanetAD\.|\/728x80topad\.|\/adchoices16\.|\/adchoicesv4\.|\/adcollector\.|\/adcontainer\?|\/addelivery\/|\/adfeedback\/|\/adfootright\.|\/AdformVideo_|\/adfoxLoader_|\/adframe728a\.|\/adframe728b\.|\/adfunctions\.|\/adgenerator\.|\/adgraphics\/|\/adhandlers2\.|\/adheadertxt\.|\/adhomepage2\.|\/adiframetop\.|\/admanagers\/|\/admetamatch\?|\/adpictures\/|\/adpolestar\/|\/adPositions\.|\/adproducts\/|\/adrequestvo\.|\/adrollpixel\.|\/adtopcenter\.|\/adtopmidsky\.|\/advcontents\.|\/advertises\/|\/advertlayer\.|\/advertright\.|\/advscripts\/|\/adzoneright\.|\/asyncadload\.|\/crossoverad\-|\/dynamiccsad\?|\/gexternalad\.|\/indexrealad\.|\/instreamad\/|\/internetad\/|\/lifeshowad\/|\/newtopmsgad\.|\/o2contentad\.|\/propellerad\.|\/showflashad\.|\/SpotlightAd\-|\/targetingAd\.|_companionad\.|\.adplacement=|\/adplacement\.|\/adversting\/|\/adversting\?|\-NewStockAd\-|\.adgearpubs\.|\.rolloverad\.|\/300by250ad\.|\/adbetween\/|\/adbotright\.|\/adboxtable\-|\/adbriteinc\.|\/adchoices2\.|\/adcontents_|\/AdElement\/|\/adexclude\/|\/adexternal\.|\/adfillers\/|\/adflashes\/|\/adFooterBG\.|\/adfootleft\.|\/adformats\/|\/adframe120\.|\/adframe468\.|\/adframetop\.|\/adhandlers\-|\/adhomepage\.|\/adiframe18\.|\/adiframem1\.|\/adiframem2\.|\/adInfoInc\/|\/adlanding\/|\/admanager3\.|\/admanproxy\.|\/admcoreext\.|\/adorika300\.|\/adorika728\.|\/adperfdemo\.|\/AdPreview\/|\/adprovider\.|\/adreplace\/|\/adrequests\.|\/adrevenue\/|\/adrightcol\.|\/adrotator2\.|\/adtextmpu2\.|\/adtopright\.|\/adv180x150\.|\/advertical\.|\/advertmsig\.|\/advertphp\/|\/advertpro\/|\/advertrail\.|\/advertstub\.|\/adviframe\/|\/advlink300\.|\/advrotator\.|\/advtarget\/|\/AdvWindow\/|\/adwidgets\/|\/adWorking\/|\/adwrapper\/|\/adxrotate\/|\/AdZoneAdXp\.|\/adzoneleft\.|\/baselinead\.|\/deliverad\/|\/DynamicAd\/|\/getvideoad\.|\/lifelockad\.|\/lightboxad[^\w.%-]|\/neudesicad\.|\/onplayerad\.|\/photo728ad\.|\/postprocad\.|\/pushdownAd\.|\/PVButtonAd\.|\/renewalad\/|\/rotationad\.|\/sidelinead\.|\/slidetopad\.|\/tripplead\/|\?adlocation=|\?adunitname=|_preorderad\.|\-adrotation\.|\/adgallery2\.|\/adgallery2$|\/adgallery3\.|\/adgallery3$|\/adinjector\.|\/adinjector_|\/adpicture1\.|\/adpicture1$|\/adpicture2\.|\/adpicture2$|\/adrotation\.|\/externalad\.|_externalad\.|\-adfliction\.|\-adfliction\/|\/adfliction\-|\/adbDetect\.|\/adbDetect\/|\/adcontrol\.|\/adcontrol\/|\/adinclude\.|\/adinclude\/|\/adkingpro\-|\/adkingpro\/|\/adoverlay\.|\/adoverlay\/|&adgroupid=|&adpageurl=|\-Ad300x250\.|\-ContentAd\-|\/125x125ad\.|\/300x250ad\.|\/ad125x125\.|\/ad160x600\.|\/ad1x1home\.|\/ad2border\.|\/ad2gather\.|\/ad300home\.|\/ad300x145\.|\/ad600x250\.|\/ad600x330\.|\/ad728home\.|\/adactions\.|\/adasset4\/|\/adbayimg\/|\/adblock26\.|\/adbotleft\.|\/adcentral\.|\/adchannel_|\/adclutter\.|\/adengage0\.|\/adengage1\.|\/adengage2\.|\/adengage3\.|\/adengage4\.|\/adengage5\.|\/adengage6\.|\/adexample\?|\/adfetcher\?|\/adfolder\/|\/adforums\/|\/adheading_|\/adiframe1\.|\/adiframe2\.|\/adiframe7\.|\/adiframe9\.|\/adinator\/|\/AdLanding\.|\/adLink728\.|\/adlock300\.|\/admarket\/|\/admeasure\.|\/admentor\/|\/adNdsoft\/|\/adonly468\.|\/adopspush\-|\/adoptions\.|\/adreclaim\-|\/adrelated\.|\/adruptive\.|\/adtopleft\.|\/adunittop$|\/advengine\.|\/advertize_|\/advertsky\.|\/advertss\/|\/adverttop\.|\/advfiles\/|\/adviewas3\.|\/advloader\.|\/advscript\.|\/advzones\/|\/adwriter2\.|\/adyard300\.|\/adzonetop\.|\/AtomikAd\/|\/contentAd\.|\/contextad\.|\/delayedad\.|\/devicead\/|\/dynamicad\?|\/fetchJsAd\.|\/galleryad\.|\/getTextAD\.|\/GetVASTAd\?|\/invideoad\.|\/MonsterAd\-|\/PageTopAD\.|\/pitattoad\.|\/prerollad\.|\/processad\.|\/ProductAd\.|\/proxxorad\.|\/showJsAd\/|\/siframead\.|\/slideinad\.|\/sliderAd\/|\/spiderad\/|\/testingad\.|\/tmobilead\.|\/unibluead\.|\/vert728ad\.|\/vplayerad\.|\/VXLayerAd\-|\/welcomead\.|=DisplayAd&|\?adcentric=|\?adcontext=|\?adflashid=|\?adversion=|\?advsystem=|\/admonitor\-|\/admonitor\.|\/adrefresh\-|\/adrefresh\.|\/defaultad\.|\/defaultad\?|\/adconfig\.|\/adconfig\/|\/addefend\.|\/addefend\/|\/adfactor\/|\/adfactor_|\/adframes\.|\/adframes\/|\/adloader\.|\/adloader\/|\/adwidget\/|\/adwidget_|\/bottomad\.|\/bottomad\/|\/buttonad\/|_buttonad\.|&adclient=|\/adclient\-|\/adclient\.|\/adclient\/|\/adblockDetector\.|\-Ad300x90\-|\-adcentre\.|\/768x90ad\.|\/ad120x60\.|\/ad1place\.|\/ad290x60_|\/ad468x60\.|\/ad468x80\.|\/AD728cat\.|\/ad728rod\.|\/adarena\/|\/adasset\/|\/adblockl\.|\/adblockr\.|\/adborder\.|\/adbot160\.|\/adbot300\.|\/adbot728\.|\/adbottom\.|\/AdBoxDiv\.|\/adboxes\/|\/adbrite2\.|\/adbucket\.|\/adbucks\/|\/adcast01_|\/adcframe\.|\/adcircle\.|\/adcodes\/|\/adcommon\?|\/adcxtnew_|\/addeals\/|\/adError\/|\/adfooter\.|\/adframe2\.|\/adfront\/|\/adgetter\.|\/adheader\.|\/adhints\/|\/adifyids\.|\/adindex\/|\/adinsert\.|\/aditems\/|\/adlantis\.|\/adleader\.|\/adlinks2\.|\/admicro2\.|\/adModule\.|\/adnotice\.|\/adonline\.|\/adpanel\/|\/adparts\/|\/adplace\/|\/adplace5_|\/adremote\.|\/adroller\.|\/adtagcms\.|\/adtaobao\.|\/adtimage\.|\/adtonomy\.|\/adtop160\.|\/adtop300\.|\/adtop728\.|\/adtopsky\.|\/adtvideo\.|\/advelvet\-|\/advert01\.|\/advert24\.|\/advert31\.|\/advert32\.|\/advert33\.|\/advert34\.|\/advert35\.|\/advert36\.|\/advert37\.|\/adverweb\.|\/adviewed\.|\/adviewer\.|\/adzilla\/|\/anchorad\.|\/attachad\.|\/bigboxad\.|\/btstryad\.|\/couponAd\.|\/customad\.|\/getmyad\/|\/gutterAd\.|\/incmpuad\.|\/injectad\.|\/insertAd\.|\/insideAD\.|\/jamnboad\.|\/jstextad\.|\/leaderad\.|\/localAd\/|\/masterad\.|\/mstextad\?|\/multiad\/|\/noticead\.|\/notifyad\.|\/pencilad\.|\/pledgead\.|\/proto2ad\.|\/salesad\/|\/scrollAd\-|\/spacead\/|\/squaread\.|\/stickyad\.|\/stocksad\.|\/topperad\.|\/tribalad\.|\/VideoAd\/|\/widgetad\.|=ad320x50\-|=adexpert&|\?adformat=|\?adPageCd=|\?adTagUrl=|_adaptvad\.|_StickyAd\.|\-adhelper\.|\/468x60ad\.|\/adhelper\.|\/admarker\.|\/admarker_|\/commonAD\.|\/footerad\.|\/footerad\?|\/headerad\.|_468x60ad\.|_commonAD\.|_headerad\.|\-admarvel\/|\.admarvel\.|\/admarvel\.|\/adometry\-|\/adometry\.|\/adometry\?|\/adcycle\.|\/adcycle\/|\/adfiles\.|\/adfiles\/|\/adpeeps\.|\/adpeeps\/|\/adproxy\.|\/adproxy\/|\/advalue\/|\/advalue_|\/adzones\.|\/adzones\/|\/printad\.|\/printad\/|\/servead\.|\/servead\/|\-adimage\-|\/adimage\.|\/adimage\/|\/adimage\?|\/get\-advert\-|\/adpixel\.|&largead=|\-adblack\-|\-adhere2\.|\/ad160px\.|\/ad2gate\.|\/ad2push\.|\/ad300f2\.|\/ad300ws\.|\/ad728f2\.|\/ad728ws\.|\/AdAgent_|\/adanim\/|\/adasync\.|\/adboxbk\.|\/adbridg\.|\/adbytes\.|\/adcache\.|\/adctrl\/|\/adedge\/|\/adentry\.|\/adfeeds\.|\/adfever_|\/adflash\.|\/adfshow\?|\/adfuncs\.|\/adgear1\-|\/adgear2\-|\/adhtml\/|\/adlandr\.|\/ADMark\/|\/admatch\-|\/admatik\.|\/adnexus\-|\/adning\/|\/adpagem\.|\/adpatch\.|\/adplan4\.|\/adpoint\.|\/adpool\/|\/adpop32\.|\/adprove_|\/adpush\/|\/adratio\.|\/adroot\/|\/adrotat\.|\/adrotv2\.|\/adtable_|\/adtadd1\.|\/adtagtc\.|\/adtext2\.|\/adtext4\.|\/adtomo\/|\/adtraff\.|\/adutils\.|\/advault\.|\/advdoc\/|\/advert4\.|\/advert5\.|\/advert6\.|\/advert8\.|\/adverth\.|\/advinfo\.|\/adVisit\.|\/advris\/|\/advshow\.|\/adweb33\.|\/adwise\/|\/adzbotm\.|\/adzerk2_|\/adzone1\.|\/adzone4\.|\/bookad\/|\/coread\/|\/flashad\.|\/flytead\.|\/gamead\/|\/hoverad\.|\/imgaad\/|\/jsonad\/|\/LayerAd[^\w.%-]|\/modalad\.|\/nextad\/|\/panelad\.|\/photoad\.|\/promoAd\.|\/rpgetad\.|\/safead\/|\/ServeAd\?|\/smartAd\?|\/transad\.|\/trendad\.|\?adclass=|&advtile=|&smallad=|\-advert3\.|\-sync2ad\-|\.adforge\.|\.admicro\.|\/adcheck\.|\/adcheck\?|\/adfetch\.|\/adfetch\?|\/adforge\.|\/adlift4\.|\/adlift4_|\/adlinks\.|\/adlinks_|\/admicro_|\/adttext\-|\/adttext\.|\/advert3\.|\/smallad\-|\/sync2ad\.|\?advtile=|\-adchain\.|\-advert2\.|\/adchain\-|\/adchain\.|\/advert2\-|\/advert2\.|\/layerad\-|\/layerad\.|_layerad\.|\/adfile\.|\/adfile\/|\/adleft\.|\/adleft\/|\/peelad\.|\/peelad\/|\/sidead\.|\/sidead\/|\/viewad\.|\/viewad\/|\/viewad\?|_sidead\.|&adzone=|\/adzone\.|\/adzone\/|\/adzone_|\?adzone=|\/adverserve\.|\/adinfo\?|\/adpv2\/|\/adtctr\.|\/adtrk\/|&adname=|&AdType=|\.adnwif\.|\.adpIds=|\/ad000\/|\/ad125b\.|\/ad136\/|\/ad160k\.|\/ad2010\.|\/ad2con\.|\/ad300f\.|\/ad300s\.|\/ad300x\.|\/ad728f\.|\/ad728s\.|\/ad728t\.|\/ad728w\.|\/ad728x\.|\/adbar2_|\/adbase\.|\/adbebi_|\/adbl1\/|\/adbl2\/|\/adbl3\/|\/adblob\.|\/adbox1\.|\/adbox2\.|\/adcast_|\/adcla\/|\/adcomp\.|\/adcss\/|\/add728\.|\/adfeed\.|\/adfly\/|\/adicon_|\/adinit\.|\/adjoin\.|\/adjsmp\.|\/adjson\.|\/adkeys\.|\/adlens\-|\/admage\.|\/admega\.|\/adnap\/|\/ADNet\/|\/adnet2\.|\/adnew2\.|\/adpan\/|\/adperf_|\/adping\.|\/adpix\/|\/adplay\.|\/AdPub\/|\/adRoll\.|\/adtabs\.|\/adtago\.|\/adunix\.|\/adutil\.|\/Adv150\.|\/Adv468\.|\/advobj\.|\/advPop\.|\/advts\/|\/advweb\.|\/adweb2\.|\/adx160\.|\/adyard\.|\/adztop\.|\/ajaxAd\?|\/baseAd\.|\/bnrad\/|\/boomad\.|\/cashad\.|\/cubead\.|\/curlad\.|\/cutead\.|\/DemoAd\.|\/dfpad\/|\/divad\/|\/drawad\.|\/ebayad\.|\/flatad\.|\/freead\.|\/fullad\.|\/geoad\/|\/GujAd\/|\/idleAd\.|\/ipadad\.|\/livead\-|\/metaad\.|\/MPUAd\/|\/navad\/|\/newAd\/|\/Nuggad\?|\/postad\.|\/railad\.|\/retrad\.|\/rollad\.|\/rotad\/|\/svnad\/|\/tinyad\.|\/toonad\.|=adMenu&|\?adarea=|\?advurl=|&adflag=|&adlist=|\.adwolf\.|\/adback\.|\/adback\?|\/adflag\.|\/adlist_|\/admain\.|\/admain$|\/adwolf\.|\/adworx\.|\/adworx_|\/footad\-|\/footad\.|\/skinad\.|_skinad\.|\.lazyad\-|\/lazyad\-|\/lazyad\.|\/widget\-advert\.|\/widget\-advert\?|\/adpic\.|\/adpic\/|\/adwiz\.|\/adwiz\/|\/flyad\.|\/flyad\/|\/adimp\?|\/adpv\/|&adnum=|\-NewAd\.|\-webAd\-|\/120ad\.|\/300ad\.|\/468ad\.|\/ad11c\.|\/ad125\.|\/ad160\.|\/ad234\.|\/ad250\.|\/ad336\.|\/ad350\.|\/ad468\.|\/adban\.|\/adbet\-|\/adbot_|\/adbtr\.|\/adbug_|\/adCfg\.|\/adcgi\?|\/adfrm\.|\/adGet\.|\/adGpt\.|\/adhug_|\/adixs\.|\/admgr\.|\/adnex\.|\/adpai\.|\/adPos\?|\/adrun\.|\/advdl\.|\/advf1\.|\/advhd\.|\/advph\.|\/advt2\.|\/adxcm_|\/adyea\.|\/affad\?|\/bizad\.|\/buyad\.|\/ciaad\.|\/cnxad\-|\/getAd;|\/ggad\/|\/KfAd\/|\/kitad\.|\/layad\.|\/ledad\.|\/mktad\.|\/mpuad\.|\/natad\.|\/picAd\.|\/pubad\.|\/subAd\.|\/txtad\.|\/ypad\/|\?adloc=|\?PopAd=|_125ad\.|_250ad\.|_FLYAD\.|\.homad\.|\.intad\.|\.intad\/|\/ad728\-|\/ad728\.|\/adrot\.|\/adrot_|\/newad\.|\/newad\?|_homad\.|\/adrum\-|\/adrum\.|\/adrum_|\/admp\-|\-ad03\.|\.adru\.|\/ad12\.|\/ad15\.|\/ad1r\.|\/ad3i\.|\/ad41_|\/ad4i\.|\/adbn\?|\/adfr\.|\/adjk\.|\/adnl\.|\/adv1\.|\/adv2\.|\/adv5\.|\/adv6\.|\/adv8\.|\/adw1\.|\/adw2\.|\/adw3\.|\/adx2\.|\/adxv\.|\/bbad\.|\/cyad\.|\/o2ad\.|\/pgad\.|\/adition\.|\.win\/ads\/|\/admeta\.|=admeta&|\/gujAd\.|\/ad8\.|\/ajax\-advert\-|\/ajax\-advert\.|\-advertising\/vast\/|\/jsad\/|\.biz\/ad2\/|\/2\/ads\/|\/ad_campaigns\/|\/ad2\/index\.|\/1\/ads\/|\/bg\-advert\-|\/telegraph\-advertising\/|\/adx\-exchange\.|\/collections\/ads\-|\/ad_contents\/|\/wp_stat\.php\?|\/Ad\.asmx\/|\/adtest\.|\/adtest\/|\/banner\.asp\?|\.com\/log\?event|\-analytics\/analytics\.|\-js\-advertising\-|\/adgallery1\.|\/adgallery1$|\/ad2\/res\/|\/img2\/ad\/|\/bottom\-advert\-|\/stream\-ad\.|\.com\/ad2\/|\.com\/js\/ad\.|\/ad\/swf\/|\/content\/adv\/|\?ad\.vid=|\-advert\-placeholder\.|\/site_under\.|\/ados\?|\/cn\-advert\.|\-gif\-advert\.|\/advs\/|\.uk\/track\?|\.nl\/ad2\/|\?advert_key=|\/scripts\/adv\.|\/clickability\-|\/clickability\/|\/clickability\?|_clickability\/|\/adv_script_|\/script\-adv\-|\-article\-advert\-|\/article\-advert\-|\/layer\-advert\-|_tracker_min\.|\/ad\/img\/|\/ad_img\.|\/ad_img\/|\?adunitid=|\/ad\.aspx\?|\/images\.adv\/|\/images\/adv\-|\/images\/adv\.|\/images\/adv\/|\/images\/adv_|\/google\/analytics\.js|\.v4\.analytics\.|\/v4\/analytics\.|\-advert\-100x100\.|\/affiliate_link\.js|\/site\-advert\.|\?adunit_id=|\/ad2\-728\-|\/e\-advertising\/|\/ad24\/|\/adsatt\.|\/wp\-admin\/admin\-ajax\.php\?action=adblockvisitor|\/native\-advertising\/|\/scripts\/ad\-|\/scripts\/ad\.|\/scripts\/ad\/|\/scripts\/ad_|\-ad\-scripts\?|\/ad\/script\/|\/ad_script\.|\/ad_script_|\-ads\-manager\/|\/ads_manager\.|\/click\-stat\.js|\-ad1\.|\/ad1_|\/wp\-srv\/ad\/|\/show_ads\.js|\/adclix\.|\/wp\-content\/plugins\/wp\-super\-popup\-pro\/|\/eureka\-ads\.|\/event\-tracking\.js|\/stats\/tracker\.js|\.php\?id=ads_|\/statistics\.php\?data=|\.com\/adds\/|\/global\-analytics\.js|\.jsp\?adcode=|\/adpicture\.|&advid=|\/ga_link_tracker_|\/adv3\.|\/ad\/afc_|\/scripts\/stats\/|\-page\-ad\.|\-page\-ad\?|\/page\/ad\/|\/adtype\.|\/adtype=|\?adtype=|\/analytics\.v1\.js|\/static\/js\/4728ba74bc\.js|\/stat\-analytics\/|\/ads_9_|\-ad\-left\.|\/ad\-left\.|\/ad_left\.|\/ad_left_|\/wp\-js\/analytics\.|\/set\-cookie\.gif\?|\/ad728x15\.|\/ad728x15_|\/images\/adds\/|\/marketing\/js\/analytics\/|\/adv_horiz\.|\/statistics\.js\?|\/ads\/zone\/|\/ads\?zone=|\/ad_entry_|\/ads300\.|\/ad\-exchange\.|\/chitika\-ad\?|\/js\/tracker\.js|\/assets\/uts\/|\-ad\.jpg\?|\.in\/ads\.|\.in\/ads\/|\.com\/log\?type|\.ws\/ads\/|\/exports\/tour\/|\/internal\-ad\-|\/adgeo\/|\/ad\/files\/|\/ad_files\/|\/files\/ad\-|\/files\/ad\/|_files\/ad\.|\/affiliate_member_banner\/|\/stats\-tracking\.js|\/adsx\/|\/js\/tracking\.js|\/adtag\.|\/adtag\/|\/adtag\?|\/adtag_|\?adtag=|\/post\-ad\-|\/images\/bg_ad\/|\.fr\/ads\.|\/b3\.php\?img=|\-adsmanager\/|\/adsmanager\/|\/wp\-content\/uploads\/useful_banner_manager_banners\/|\/corner\-ad\.|\/yandex\-metrica\-watch\/|\/adp\-pro\/|\/gravity\-beacon\.js|\/ad_multi_|\/vs\-track\.js|\/popad\-|\/popad\.|\/ad_horiz\.|\/webmaster_ads\/|_temp\/ad_|\$csp=worker\-src 'none',domain=estream\.to$flashx\.cc$flashx\.co$flashx\.co$streamango\.com$vidoza\.co$vidoza\.net$vidto\.me$vidto\.se$vidtudu\.com|\/wp\-content\/plugins\/anti\-block\/|\/adv\.php|\/ad\-hcm\.|\/tracking_link_cookie\.|\.hr\/ads\.|\/story_ad\.|\-adv\-v1\/|\-ads\-placement\.|\/addyn\/3\.0\/|\-ad\-random\/|\/ad\/random_|\/log_stats\.php\?|\/AdvertAssets\/|\/ad\-blocker\.js|\/aff_banner\/|\/Ad\/Oas\?|\.com\/adv\/|\.com\/adv\?|\.com\/adv_|\/widget\/ad\/|_widget_ad\.|\/assets\/adv\/|\/adx_flash\.|\/ads_openx_|\/reklam\-ads2\.|\/ad_campaign\?|\/ad\.min\.|\/stat\.php\?|\/all\/ad\/|\?event=advert_|\/ad\/cross\-|\.xyz\/ads\/|\.net\/affiliate\/|\/adz\/images\/|\/lib\/ad\.js|\/publisher\.ad\.|\/images\/adz\-|\/images\/adz\/|\/rcom\-video\-ads\.|\/ads\.json\?|\/pagead\.|\/pagead\?|\/adzonesidead\.|\/adv_image\/|\/image\/adv\/|\/partner\/transparent_pixel\-|&admeld_|\/admeld\.|\/admeld\/|\/admeld_|=admeld&|\/cpx\-ad\.|\/ad\-third\-party\/|\/context_ad\/|\/trackings\/addview\/|\/advpreload\.|\.tv\/adl\.|\/250x250\-adverts\.|\/analytics\-assets\/|\-ads\/oas\/|\/ads\/oas\-|\/ads\/oas\/|\/assets\/analytics\:|\/Cookie\?merchant=|\/_30\/ads\/|\/Article\-Ad\-|\/ads\/xtcore\.|\/adclixad\.|\/adreload\.|\/adreload\?|\/pub\/js\/ad\.|\/bi_affiliate\.js|\-load\-advert\.|\/md\.js\?country=|\/tracker_czn\.tsp\?|\/adifyad\.|\/rtt\-log\-data\?|\/youtube\-track\-event_|\/impressions\/log\?|\/ad\/generate\?|\/generate_ad\.|\/websie\-ads\-|\/adv_top\.|\/addLinkerEvents\-std\.|\-your\-ad\-here\-|\-ads\/video\.|\/ads\/video\/|\/ads\/video_|\/adload\.|\/create\-lead\.js|&adsize=|\?adsize=|\/affiliate\-assets\/banner\/|\/ad_rotation\.|\/assets\/ad\-|\/assets\/ad\/|\/adblock\.js|\/tracker\.json\.php\?|\/client\-event\-logger\.|\/active\-ad\-|\/ip\-advertising\/|\/tracking_add_ons\.|\/assets\/tracking\-|\/pagead\/ads\?|\/wp\-content\/plugins\/deadblocker\/|\-amazon\-ads\/|\/affiliate\/ads\/|\/ad\/timing\.|\/libs\/tracker\.js|\/tracking\.js\?site_id=|\/pixiedust\-build\.js|\-gallery_ad\/|\/search\-cookie\.aspx\?|\/admin\/banners\/|\/ad\/display\.php|\/nd_affiliate\.|\/affiliates\/contextual\.|\/affiliate\.linker\/|\/ad\-builder\.|\-advertisement\/script\.|\/affiliate\.1800flowers\.|\/affiliate\/displayWidget\?|\/ads\/branding\/|\/pickle\-adsystem\/|\/mail_tracking\-cg\.php|\/share\/ads\/|\/ad_medium_|\/ads\-rec$|\/ads\/navbar\/|\/wp\-content\/tracker\.|\/affiliate_show_banner\.|\-load\-ads\.|\/load\-ads$|\/ads\.load\.|\/ads\/load\.|\/ads_load\/|\/ads\-admin\.|\/affiliate_base\/banners\/|\/ade\/baloo\.php|_ads\-affiliates_|\/ajax\-ad\/|\/ajax\/ad\/|\/adv\/topBanners\.|\/utm_cookie\.|\/promo\/ad_|_promo_ad\/|\/sponsor%20banners\/|\/comscore_beacon\.|\/adv\/bottomBanners\.|\/ad_mini_|\/adsmm\.dll\/|\/adv\/mjx\.|\/3rd\-party\-stats\/|\/affiliate\/small_banner\/|\/ads\/contextual\.|\/ads\/contextual_|\-advert_August\.|\/ads\/head\.|\/idevaffiliate\/banners\/|\/plugin\/trackEvents\.|\/CookieManager\-bdl\?|\/trackingfilter\.json\?|\/akamai_analytics_|\/skype\-analytics\.|\.net\/flashads|\/dmn\-advert\.|\/ads\-common\.|\/ads\/common\/|\/adblock\-relief\/|\/tracked_ad\.|\/watchonline_cookies\.|\/p2\/ads\/|\/cookie\?affiliate|\-simple\-ads\.|\-theme\/ads\/|_theme\/ads\/|\/adbrite\-|\/adbrite\.|\/adbrite\/|\/adbrite_|\/flashtag\.txt\?Log=|\/econa\-site\-search\-ajax\-log\-referrer\.php|\/watch\?shu=|\/button_ads\/|\/admvn_pop\.|\/event\?t=view&|\/ga_no_cookie\.|\/ga_no_cookie_|\/im\-ad\/im\-rotator2\.|\/ifolder\-ads\.|\/zalando\-ad\-|\/sitetestclickcount\.enginedocument,script,subdocument|\/init_cookie\.php\?|\/analytics\/urlTracker\.|\/adjs\.|\/adjs\/|\/adjs\?|\/adjs_|\/ads_ifr\.|\/websie\-ads3\.|\/ad\-catalogue\-|\/gen_ads_|\/polopoly_fs\/ad\-|\?event=performancelogger\:|\/tracker\/eventBatch\/|\/track\.php\?referrer=|\.ad\-ocad\.|\-ads\/static\-|_stat\/addEvent\/|\/ads\?cookie_|\/ads\-03\.|\/ads\/tso|\-ads\-180x|\/ads\-arc\.|\/ads\-cch\-|\/ads\.w3c\.|\/ads\/cbr\.|\/ads\/im2\.|\/ads\?apid|\/ems\/ads\.|\/ia\/ads\/|\/old\/ads\-|\/ome\.ads\.|\/sni\-ads\.|\/tit\-ads\.|\/v7\/ads\/|\/vld\.ads\?|\/ads_door\.|\/ads\/creatives\/|\/bci\-ads\.|\/bci\-ads\/|\/ads\/125l\.|\/ads\/125r\.|\/ads\/3002\.|\/ads\/468a\.|\/ads\/728b\.|\/ads\/mpu2\?|\/ads\/narf_|\/ads_gnm\/|\/ast\/ads\/|\/cvs\/ads\/|\/dxd\/ads\/|\/esi\/ads\/|\/inv\/ads\/|\/mda\-ads\/|\/sbnr\.ads\?|\/smb\/ads\/|\/ss3\/ads\/|\/tmo\/ads\/|\/tr2\/ads\/|\/ads\/daily\.|\/ads\/daily_|\/comscore_engine\.|\.refit\.ads\.|\/1912\/ads\/|\/ads\-mopub\?|\/ads\-nodep\.|\/ads\/\?QAPS_|\/ads\/getall|\/ads\/gray\/|\/ads\/like\/|\/ads\/smi24\-|\/bauer\.ads\.|\/img3\/ads\/|\/ispy\/ads\/|\/kento\-ads\-|\/libc\/ads\/|\/subs\-ads\/|\/wire\/ads\/|_html5\/ads\.|\/door\/ads\/|\-ads\-530x85\.|\-intern\-ads\/|\/ads\-inside\-|\/ads\-intros\.|\/ads\.compat\.|\/ads\/acctid=|\/ads\/banid\/|\/ads\/bilar\/|\/ads\/box300\.|\/ads\/oscar\/|\/ads\?spaceid|\/ads_codes\/|\/ads_medrec_|\/ads_patron\.|\/ads_sprout_|\/cmlink\/ads\-|\/cssjs\/ads\/|\/digest\/ads\.|\/doors\/ads\/|\/dpics\/ads\/|\/gawker\/ads\.|\/minify\/ads\-|\/skin3\/ads\/|\/webapp\/ads\-|\?ads_params=|\/hostkey\-ad\.|\/daily\/ads\/|\-contrib\-ads\.|\-contrib\-ads\/|\-ads\-Feature\-|\/aderlee_ads\.|\/ads\-reviews\-|\/ads\.jplayer\.|\/ads\/250x120_|\/ads\/300x120_|\/ads\/behicon\.|\/ads\/labels\/|\/ads\/pencil\/|\/ads\/square2\.|\/ads\/square3\.|\/cactus\-ads\/|\/campus\/ads\/|\/develop\/ads_|\/expandy\-ads\.|\/outline\-ads\-|\/uplimg\/ads\/|\/xfiles\/ads\/|\/ads\-sticker2\.|\/ads\.release\/|\/ads\/cnvideo\/|\/ads\/masthead_|\/ads\/mobiles\/|\/ads\/reskins\/|\/ads\/ringtone_|\/ads\/serveIt\/|\/central\/ads\/|\/cramitin\/ads_|\/gazette\/ads\/|\/hpcwire\/ads\/|\/jetpack\-ads\/|\/jsfiles\/ads\/|\/magazine\/ads\.|\/playerjs\/ads\.|\/taxonomy\-ads\.|\/ads\/webplayer\.|\/ads\/webplayer\?|\/ads\-mobileweb\-|\/ads\-segmentjs\.|\/ads\/leaderbox\.|\/ads\/proposal\/|\/ads\/sidedoor\/|\/ads\/swfobject\.|\/calendar\-ads\/|\/editable\/ads\/|\/releases\/ads\/|\/rule34v2\/ads\/|\/teaseimg\/ads\/|\/ad_bannerPool\-|\/bannerfile\/ad_|\/ads\/inner_|\-floorboard\-ads\/|\/ads\/htmlparser\.|\/ads\/postscribe\.|\/fileadmin\/ads\/|\/moneyball\/ads\/|\/permanent\/ads\/|\/questions\/ads\/|\/standalone\/ads\-|\/teamplayer\-ads\.|\/inner\-ads\-|\/inner\-ads\/|\/ads\/728x90above_|\/ads\/indexmarket\.|\/excellence\/ads\/|\/userimages\/ads\/|\-ads\/videoblaster\/|\/ads\-restrictions\.|\/ads\/displaytrust\.|\/ads\/scriptinject\.|\/ads\/writecapture\.|\/colorscheme\/ads\/|\/configspace\/ads\/|\/homeoutside\/ads\/|\/incotrading\-ads\/|\/ads\/generator\/|\/ad\/superbanner\.|\/ads\/checkViewport\.|\/ads\/welcomescreen\.|\/photoflipper\/ads\/|\/tracking\/comscore\/|\/ads\/generatedHTML\/|\/ad_fixedad\.|\/customcontrols\/ads\/|\/ads\/contextuallinks\/|\/track_general_stat\.|\/no\-adblock\/|\/ads\/elementViewability\.|\/ads\/menu_|\/ads\/exo_|\.lazyload\-ad\-|\.lazyload\-ad\.|\/ad_lazyload\.|\/ad\/js\/banner9232\.|\/ads\-blogs\-|\/carousel_ads\.|\/doubleclick_head_tag_|\.html\?ad=|\.html\?ad_|\/html\/ad\.|\/html\/ad\/|\/affiliate_show_iframe\.|\/comscore\/streamsense\.|\-analitycs\/\/metrica\.|\-analitycs\/metrica\.|\/ads\-scroller\-|\/wp\-content\/plugins\/bookingcom\-banner\-creator\/|\-ad\-cube\.|\/ads\/original\/|\/ad_selectMainfixedad\.|\/ajaxLogger_tracking_|\/adonis_event\/|\/js_log_error\.|\/google\-nielsen\-analytics\.|\?eventtype=request&pid=|\/adv_flash\.|\/04\/ads\-|\/ads\-04\.|\/tracking\/setTracker\/|\/track_yt_vids\.|\/cgi\-sys\/count\.cgi\?df=|\/ad_system\/|\/ilivid\-ad\-|\-ad\-gif\-|\/ad\.gif$|\/ad_gif\/|\/ad_gif_|_ad\.gif$|\/json\/ad\/|\/traffic\-source\-cookie\.|\/traffic\-source\-cookie\/|\.cfm\?advideo%|\/hosting\/ads\/|\/include\/adsdaq|\.widgets\.ad\?|\/javascript\/ads\.|\/javascript\/ads\/|\.ad\.json\?|\/json\/tracking\/|\/tncms\/ads\/|\/ads\/adv\/|\/adv\/ads\/|\/php\-stats\.phpjs\.php\?|\/php\-stats\.recjs\.php\?|\/banner\.ws\?|\/ads\-05\.|\/ad\/ad2\/|\/adv\.png|\/tracker\/trackView\?|\/affiliate\-tracker\.|\/ads\/create_|\/cookie\/visitor\/|\/scripts\/tracking\.js|\/ad\/window\.php\?|=get_preroll_cookie&|\/shared\/ads\.|\/shared\/ads\/|\/addon\/analytics\/|\/ads\/popup\.|\/ads\/popup_|\-popup\-ads\-|\/analytics\.json\?|\-adverts\.libs\.|\/log_zon_img\.|\/adv\-scroll\-|\/adv\-scroll\.|\/GoogleAnalytics\?utmac=|\/tracker\-ev\-sdk\.js|\/ads\-06\.|\/ads\/drive\.|\/tops\.ads\.|\/dynamic\-ad\-|\/dynamic\-ad\/|\/simple\-tracking\?|\.am\/adv\/|\/watchit_ad\.|\/metrics\-VarysMetrics\.|\/magic\-ads\/|\/country_ad\.|\/adv\.css\?|\/css\/adv\.|\/adv\.jsp|\/monetization\/ads\-|\/khan_analystics\.js|\/ads\.pbs|\/analys\/dep\/|\/scripts\/AdService_|\/silver\/ads\/|\/ad_onclick\.|\/ad\-sovrn\.|\/event\/rumdata\?|\/plugins\/status\.gif\?|\/ads_event\.|\/adm_tracking\.js|\/iva_thefilterjwanalytics\.|\/ads\/motherless\.|\/xtanalyzer_roi\.|\/bftv\/ads\/|\/ad\/special\.|\/special_ad\.|\/bsc_trak\.|\/track\-compiled\.js|\/ads\-01\.|\/log\?sLog=|\/ads\/configuration\/|\/trackv&tmp=|\/linktracking\.|\/session\-tracker\/tracking\-|\-Results\-Sponsored\.|\/comscore_stats\.|\/lead\-tracking\.|\/lead\-tracking\/|\/ads\-leader$|\/tracking\/digitalData\.|\/wp\-content\/mbp\-banner\/|\/meas\.ad\.pr\.|\/tracker\-config\.js|\-ad\-reload\.|\-ad\-reload\/|\-strip\-ads\-|\/msn\-exo\-|\/gcui_vidtracker\/|\/tracking\.relead\.|\-ads\-master\/|\/related\-ads\.|\/sbtracking\/pageview2\?|\/styles\/ads\.|\/styles\/ads\/|\/ima\/ads_|\/ads\/select\/|\/gen\-ad\-|\/AdCookies\.js|\/fm\-ads1\.|\/cookie\.crumb|\/ads\-07\.|\/sitefiles\/ads\/|\/analiz\.php3\?|\/fora_player_tracking\.|\/ads\-beacon\.|\/ads\/beacon\.|\/beacon\/ads\?|\/analytics\.bundled\.js|\/qpon_big_ad|\/smedia\/ad\/|\/atcode\-bannerize\/|\/tracking\/user_sync_widget\?|\/analytics\.config\.js|\/compiled\/ads\-|\/tracking\-jquery\-shim\.|\/affiliate\-track\.|\/affiliate\.track\?|\/affiliate\/track\?|\/propagate_cookie\.|\/layout\/ads\/|\/jsc\/ads\.|\/2011\/ads\/|\/stat\/eventManager\/|\/ad_links\/|\/logo\-ads\.|\/logo\/ads_|_ads_v8\.|\/ad\-callback\.|\/u\-ads\.|\/u\/ads\/|\/seosite\-tracker\/|\/ads\/real_|\/intermediate\-ad\-|\/3pt_ads\.|\/fea_ads\.|\/gtv_ads\.|\/qd_ads\/|\/adblock\?id=|\/big\-ad\-switch\-|\/big\-ad\-switch\/|=big\-ad\-switch_|\/stuff\/ad\-|\-ads\-tracking\-|\/ads_tracking\.|\/tracking\/ads\.|_ajax\/btrack\.php\?|\/client\-event\.axd\?|\-ads\.generated\.|\/ads\-rectangle\.|\/ads\/rectangle_|\/jkidd_cookies\?|\/ad_tpl\.|\/WritePartnerCookie\?|\/digg_ads\.|\/digg_ads_|\/eco_ads\/|\/flag_ads\.|\/ges_ads\/|\/m0ar_ads\.|\/miva_ads\.|_ads_Home\.|_ads_only&|\/ads\/community\?|\/defer_ads\.|\/ifrm_ads\/|\/tracking\/xtcore\.|\/adlabs\.js|\/ads_common_library\.|\/chorus_ads\.|\/torget_ads\.|_ads_single_|\/track\/pix2\.asp\?|\/demo\/ads\/|_ads_updater\-|_rightmn_ads\.|_ads\/inhouse\/|\/ads\/profile\/|\/Javascripts\/Gilda\-May\.js|\/ads~adsize~|\/inhouse_ads\/|\/included_ads\/|_ads_framework\.|\/adbl_dtct\.|\/ajx\/ptrack\/|\/imagecache_ads\/|\/beacon\-cookie\.|\/ADV\/Custom\/|\/tracking\/track\.jsp\?|\/affiliation_banners\/|\/videostreaming_ads\.|\/ads\.bundle\.|\/bundle\/ads\.|\/ads\/imbox\-|\/rcom\-ads\-|\/rcom\-ads\.|\/wp\-content\/plugins\/automatic\-social\-locker\/|\/adwords\-conversion\-tracking\.|\/TILE_ADS\/|\/autotrack\.carbon\.js|_ads_contextualtargeting_|\/buyer\/dyad\/|\/ad\/extra\/|\/ad\/extra_|\/assets\/ads3\-|\/adlog\.php\?|\/Affiliate\-Banner\-|\/ad1\/index\.|&adserv=|\.adserv\/|\/adserv\.|\/adserv\/|\/adserv_|\/ads\/freewheel\/|\/entry\.count\.image\?|\/ads\/rail\-|\-rail\-ads\.|\-rail\-ads\/|\/storage\/adv\/|\/serv\.ads\.|\/ez_aba_load\/|\/showcode\?adids=|\/track\/\?site|\/track\/site\/|\/sponsors\/amg\.php\?|\/Ad\/premium\/|\/xml\/ad\/|\/tracker\-r1\.js|\/ads_tracker\.|\/ads\/tracker\/|\/datacapture\/track|\/ads_premium\.|\/ad\.cgi\?|\.cgi\?ad=|\/cgi\/ad_|\/adim\.html\?ad|\/ads\/frontpage\/|\/curveball\/ads\/|\/tracker\-setting\.js|\/A\-LogAnalyzer\/|_ads_control\.|\/pix\/ads\/|\/AdBlockDetection\/scriptForGA\.|\/ad\/p\/jsonp\?|\/vision\/ads\/|\/iframe_googleAnalytics|\/17\/ads\/|\-ads\/ad\-|\/ads\/ad\-|\/ads\/ad\.|\/ads\/ad_|\/ads_ad_|\/ad%20banners\/|\/stats_brand\.js|\/stats\/Logger\?|_stats\/Logger\?|\/log\/jserr\.php|\/ads\/pop\.|\/track\-internal\-links\.|\/ads\/rect_|\-doubleclick\.js|\/newimages\/ads\/|\/blogtotal_stats_|\/securepubads\.|\/impressions\/(?=([\s\S]*?\/track))\1|\/track\/(?=([\s\S]*?&CheckCookieId=))\2|\/track\/(?=([\s\S]*?&siteurl=))\3|\/promoredirect\?(?=([\s\S]*?&campaign=))\4(?=([\s\S]*?&zone=))\5|\/images\/a\.gif\?(?=([\s\S]*?=))\6|\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline',domain=fflares\.com$fileflares\.com$ibit\.to$piratbaypirate\.link$unblocktheship\.org$noobnoob\.rocks$indiaproxydl\.org$magnetbay\.eu$airproxyproxy\.pw$thepirate\.xyz$pietpiraat\.org$ahoypirate\.in$tpb\.tw$proxyindia\.net$thepiratebay\.blue$ahoypiratebaai\.eu$pirate\.bet$airproxytpb\.red$ikwildepiratebay\.xyz$piratebay\.tel$bayception\.pw$piratebay\.town$superbay\.link$thepiratebay\.kiwi$tpb\.one$baypirateproxy\.pw$rarbgmirrored\.org$rarbgmirror\.org$rarbg\.to$rarbgaccess\.org$rarbgmirror\.com$rarbgmirror\.xyz$rarbgproxy\.org$rarbgprx\.org$mrunlock\.pro$downloadpirate\.com$prox4you\.xyz$123unblock\.info$nocensor\.icu$unlockproject\.live$pirateproxy\.bet$thepiratebay\.vip$theproxybay\.net$thepiratebay\.tips$thepiratebay10\.org$prox1\.info$kickass\.vip$torrent9\.uno$torrentsearchweb\.ws$pirateproxy\.app$ukpass\.co$theproxybay\.net$thepiratebay\.tips$prox\.icu$proxybay\.ga$pirateproxy\.life$piratebae\.co\.uk$berhampore\-gateway\.ml$ikwilthepiratebay\.org$thepiratebay10\.org$bayfortaiwan\.online$unblockthe\.net$cruzing\.xyz))\7|\$csp=child\-src 'none'; frame\-src (?=([\s\S]*?; worker\-src 'none',domain=adfreetv\.ch$ddmix\.net$extratorrent\.cd$gofile\.io$hq\-porns\.com$intactoffers\.club$myfeed4u\.net$reservedoffers\.club$skyback\.ru$szukajka\.tv$thepiratebay\.cr$thepiratebay\.org$thepiratebay\.red$thevideo\.cc$thevideo\.ch$thevideo\.io$thevideo\.me$thevideo\.us$tvad\.me$vidoza\.net$vidup\.me))\8|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?cpx\.to))\9|\.us\/ad\/(?=([\s\S]*?\?))\10|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?mc\.yandex\.ru))\11|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?revcontent\.com))\12|\/cdn\-cgi\/pe\/bag\?r(?=([\s\S]*?cpalead\.com))\13|\/widgets\/adverts\/(?=([\s\S]*?\.))\14|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?viglink\.com))\15|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?contextual\.media\.net))\16|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?static\.getclicky\.com%2Fjs))\17|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?googleadservices\.com))\18|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?clkrev\.com))\19|\$csp=child\-src 'none'; frame\-src 'self' (?=([\s\S]*?; worker\-src 'none',domain=fileone\.tv$theappguruz\.com))\20|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?nr\-data\.net))\21|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?google\-analytics\.com%2Fanalytics\.js))\22|\/cdn\-cgi\/pe\/bag\?r(?=([\s\S]*?pubads\.g\.doubleclick\.net))\23|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?cdn\.onthe\.io%2Fio\.js))\24|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?content\.ad))\25|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?hs\-analytics\.net))\26|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?geoiplookup))\27|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?chartbeat\.js))\28|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?log\.outbrain\.com))\29|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?adsnative\.com))\30|\/cdn\-cgi\/pe\/bag2\?r\[\]=(?=([\s\S]*?eth\-pocket\.de))\31|\/\?com=visit(?=([\s\S]*?=record&))\32|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.qualitypublishers\.com))\33|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.worldoffersdaily\.com))\34|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?eclkmpbn\.com))\35|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?eclkspsa\.com))\36|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?bounceexchange\.com))\37|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.codeonclick\.com))\38|\?AffiliateID=(?=([\s\S]*?&campaignsVpIds=))\39|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.amazonaws\.com))\40(?=([\s\S]*?secure\.js))\41|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?zwaar\.org))\42|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?az708531\.vo\.msecnd\.net))\43|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.zergnet\.com))\44|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?\.speednetwork1\.com))\45|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?revdepo\.com))\46|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?bnserving\.com))\47|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?linksmart\.com))\48|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?puserving\.com))\49|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?intellitxt\.com))\50|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?scorecardresearch\.com))\51|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.content\-ad\.net))\52|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?\.google\-analytics\.com))\53|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?newrelic\.com))\54|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?adk2\.co))\55|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?pipsol\.net))\56|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?popcash\.net))\57|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?juicyads\.com))\58|\/Redirect\.(?=([\s\S]*?MediaSegmentId=))\59|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?quantserve\.com))\60|\/Log\?(?=([\s\S]*?&adID=))\61|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?mellowads\.com))\62|\?zoneid=(?=([\s\S]*?_bannerid=))\63|\/g00\/(?=([\s\S]*?\/clientprofiler\/adb))\64|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?adsrvmedia))\65|^javascript\:(?=([\s\S]*?window\.location))\66|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?popads\.net))\67|=event&(?=([\s\S]*?_ads%))\68|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?yieldbot\.intent\.js))\69|\/analytics\/(?=([\s\S]*?satellitelib\.js))\70|\/affiliates\/(?=([\s\S]*?\/show_banner\.))\71)/i;
var bad_url_parts_flag = 2579 > 0 ? true : false;  // test for non-zero number of rules
    
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
