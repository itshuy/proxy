// PAC (Proxy Auto Configuration) Filter from EasyList rules
// 
// Copyright (C) 2017 by Steven T. Smith <steve dot t dot smith at gmail dot com>, GPL
// https://github.com/essandess/easylist-pac-privoxy/
//
// PAC file created on Fri, 31 May 2019 19:04:49 GMT
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
"exoclick.com": null,
"webvisor.ru": null,
"nastydollars.com": null,
"adziff.com": null,
"tsyndicate.com": null,
"sharethrough.com": null,
"amazon-adsystem.com": null,
"ad.doubleclick.net": null,
"dianomi.com": null,
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
"advertising.com": null,
"chartbeat.com": null,
"adult.xyz": null,
"media.net": null,
"nuggad.net": null,
"teads.tv": null,
"static.parsely.com": null,
"click.aliexpress.com": null,
"imasdk.googleapis.com": null,
"webtrekk.net": null,
"smartadserver.com": null,
"log.pinterest.com": null,
"adnxs.com": null,
"movad.net": null,
"clicktale.net": null,
"mxcdn.net": null,
"stroeerdigitalmedia.de": null,
"flashtalking.com": null,
"rlcdn.com": null,
"adverserve.net": null,
"intelliad.de": null,
"d11a2fzhgzqe7i.cloudfront.net": null,
"krxd.net": null,
"visualwebsiteoptimizer.com": null,
"cm.g.doubleclick.net": null,
"crwdcntrl.net": null,
"gitcdn.pw": null,
"banners.cams.com": null,
"hotjar.com": null,
"imglnkc.com": null,
"3lift.com": null,
"ace.advertising.com": null,
"revcontent.com": null,
"eclick.baidu.com": null,
"adform.net": null,
"xxlargepop.com": null,
"quantserve.com": null,
"adition.com": null,
"cpx.to": null,
"mediaplex.com": null,
"bluekai.com": null,
"openx.net": null,
"ad.proxy.sh": null,
"lw2.gamecopyworld.com": null,
"adapd.com": null,
"bontent.powvideo.net": null,
"adfox.yandex.ru": null,
"bongacams.com": null,
"adx.kat.ph": null,
"traffic.focuusing.com": null,
"adspayformymortgage.win": null,
"pixel.ad": null,
"adc.stream.moe": null,
"firstclass-download.com": null,
"ad.rambler.ru": null,
"adv.drtuber.com": null,
"ebayobjects.com.au": null,
"trmnsite.com": null,
"pdheuryopd.loan": null,
"yinmyar.xyz": null,
"nkmsite.com": null,
"clickopop1000.com": null,
"videoplaza.com": null,
"uoldid.ru": null,
"money-maker-script.info": null,
"money-maker-default.info": null,
"kdmkauchahynhrs.ru": null,
"megabanners.cf": null,
"abbp1.website": null,
"cashbigo.com": null,
"freecontent.download": null,
"ero-advertising.com": null,
"creativecdn.com": null,
"ads.yahoo.com": null,
"pos.baidu.com": null,
"abbp1.science": null,
"chartaca.com.s3.amazonaws.com": null,
"heapanalytics.com": null,
"ct.pinterest.com": null,
"adup-tech.com": null,
"getclicky.com": null,
"popads.net": null,
"adlink.net": null,
"advertserve.com": null,
"dnn506yrbagrg.cloudfront.net": null,
"log.outbrain.com": null,
"3wr110.xyz": null,
"smallseotools.com": null,
"bzclk.baidu.com": null,
"gsp1.baidu.com": null,
"juicyads.com": null,
"metrics.brightcove.com": null,
"adk2.co": null,
"pixel.facebook.com": null,
"hornymatches.com": null,
"adonweb.ru": null,
"prpops.com": null,
"adcash.com": null,
"htmlhubing.xyz": null,
"adtrace.org": null,
"onad.eu": null,
"videoplaza.tv": null,
"admedit.net": null,
"adexc.net": null,
"sexad.net": null,
"mobsterbird.info": null,
"explainidentifycoding.info": null,
"am10.ru": null,
"xclicks.net": null,
"utarget.ru": null,
"adjuggler.net": null,
"adk2.com": null,
"adbooth.com": null,
"popwin.net": null,
"rapidyl.net": null,
"insta-cash.net": null,
"clicksor.net": null,
"hd-plugin.com": null,
"contentabc.com": null,
"propellerpops.com": null,
"liveadexchanger.com": null,
"ringtonematcher.com": null,
"superadexchange.com": null,
"downloadboutique.com": null,
"clicksor.com": null,
"adexchangeprediction.com": null,
"adnetworkperformance.com": null,
"august15download.com": null,
"bentdownload.com": null,
"adultadworld.com": null,
"admngronline.com": null,
"adxpansion.com": null,
"brucelead.com": null,
"venturead.com": null,
"ad-maven.com": null,
"hpr.outbrain.com": null,
"ad4game.com": null,
"adplxmd.com": null,
"adrunnr.com": null,
"adxprtz.com": null,
"clickmngr.com": null,
"ad131m.com": null,
"ad2387.com": null,
"adnium.com": null,
"adxite.com": null,
"alternads.info": null,
"adbma.com": null,
"adk2x.com": null,
"sharecash.org": null,
"xtendmedia.com": null,
"clicktripz.com": null,
"widget.yavli.com": null,
"tracking-rce.veeseo.com": null,
"media-servers.net": null,
"ad6media.fr": null,
"888media.net": null,
"bullads.net": null,
"pwrads.net": null,
"whoads.net": null,
"collector.contentexchange.me": null,
"kissmetrics.com": null,
"brandreachsys.com": null,
"livepromotools.com": null,
"tagcdn.com": null,
"c4tracking01.com": null,
"perfcreatives.com": null,
"click.scour.com": null,
"statsmobi.com": null,
"clickosmedia.com": null,
"ringtonepartner.com": null,
"bettingpartners.com": null,
"youradexchange.com": null,
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
"traffictraffickers.com": null,
"trafficholder.com": null,
"trafficforce.com": null,
"yieldtraffic.com": null,
"traffichaus.com": null,
"trafficshop.com": null,
"fpctraffic2.com": null,
"hipersushiads.com": null,
"epicgameads.com": null,
"affbuzzads.com": null,
"megapopads.com": null,
"down1oads.com": null,
"popmyads.com": null,
"filthads.com": null,
"padsdel.com": null,
"1phads.com": null,
"adblade.com": null,
"stats.bitgravity.com": null,
"traktrafficflow.com": null,
"track.xtrasize.nl": null,
"onclickads.net": null,
"advmedialtd.com": null,
"adultadmedia.com": null,
"pointclicktrack.com": null,
"adcdnx.com": null,
"360adstrack.com": null,
"adscpm.net": null,
"shareasale.com": null,
"adsrv4k.com": null,
"adsurve.com": null,
"adservme.com": null,
"adsupply.com": null,
"adserverplus.com": null,
"adglare.org": null,
"adexchangetracker.com": null,
"adswizz.com": null,
"adsmarket.com": null,
"pubads.g.doubleclick.net": null,
"webcams.com": null,
"perfectmarket.com": null,
"reallifecam.com": null,
"freecontent.science": null,
"tubeadvertising.eu": null,
"freecontent.win": null,
"popshow.info": null,
"urlcash.net": null,
"abctrack.bid": null,
"hm.baidu.com": null,
"addmoredynamiclinkstocontent2convert.bid": null,
"advertiserurl.com": null,
"xxxmatch.com": null,
"adfox.ru": null,
"showcase.vpsboard.com": null,
"adport.io": null,
"bestforexplmdb.com": null,
"freecontent.trade": null,
"patiskcontentdelivery.info": null,
"ad.smartclip.net": null,
"flcounter.com": null,
"tostega.ru": null,
"adm.shinobi.jp": null,
"plugin.ws": null,
"adexchangemachine.com": null,
"adexchangegate.com": null,
"adhealers.com": null,
"admeerkat.com": null,
"adright.co": null,
"aj1574.online": null,
"adtgs.com": null,
"core.queerclick.com": null,
"trackvoluum.com": null,
"zymerget.win": null,
"flagads.net": null,
"popcash.net": null,
"b.photobucket.com": null,
"hodling.science": null,
"pr-static.empflix.com": null,
"histats.com": null,
"adop.cc": null,
"iwebanalyze.com": null,
"adglare.net": null,
"9content.com": null,
"hawkeye-data-production.sciencemag.org.s3-website-us-east-1.amazonaws.com": null,
"predictivadvertising.com": null,
"bestquickcontentfiles.com": null,
"metricfast.com": null,
"showcasead.com": null,
"fastclick.net": null,
"vtracker.net": null,
"trackmytarget.com": null,
"cookiescript.info": null,
"topad.mobi": null,
"premium.naturalnews.tv": null,
"ozon.ru": null,
"intab.xyz": null,
"affiliate.mediatemple.net": null,
"synthasite.net": null,
"campanja.com": null,
"xs.mochiads.com": null,
"affiliatesmedia.sbobet.com": null,
"jshosting.win": null,
"nextoptim.com": null,
"mellowads.com": null,
"indieclick.com": null,
"jshosting.science": null,
"adboost.it": null,
"pc.thevideo.me": null,
"vserv.bc.cdn.bitgravity.com": null,
"adhome.biz": null,
"stats.ibtimes.co.uk": null,
"whatismyip.win": null,
"ams.addflow.ru": null,
"mobtop.ru": null,
"cookietracker.cloudapp.net": null,
"webcounter.ws": null,
"googleadservices.com": null,
"webstats.com": null,
"codeonclick.com": null,
"count.livetv.ru": null,
"backlogtop.xyz": null,
"afimg.liveperson.com": null,
"hilltopads.net": null,
"tracking.moneyam.com": null,
"cdnmedia.xyz": null,
"bonzai.ad": null,
"ingame.ad": null,
"spider.ad": null,
"cklad.xyz": null,
"popunderjs.com": null,
"gstaticadssl.l.google.com": null,
"advserver.xyz": null,
"analytics.us.archive.org": null,
"buythis.ad": null,
"gocp.stroeermediabrands.de": null,
"ufpcdn.com": null,
"wmemsnhgldd.ru": null,
"tracklab.club": null,
"affiliates-cdn.mozilla.org": null,
"clickredirection.com": null,
"affiliatehub.skybet.com": null,
"onclicksuper.com": null,
"pulseonclick.com": null,
"topclickguru.com": null,
"onclickmega.com": null,
"revimedia.com": null,
"vpnaffiliates.hidester.com": null,
"analytics.163.com": null,
"s11clickmoviedownloadercom.maynemyltf.netdna-cdn.com": null,
"topbinaryaffiliates.ck-cdn.com": null,
"trackingpro.pro": null,
"premiumstats.xyz": null,
"getalinkandshare.com": null,
"fdxstats.xyz": null,
"popunder.ru": null,
"youroffers.win": null,
"affiliate.iamplify.com": null,
"mytrack.pro": null,
"affiliate.mercola.com": null,
"cloudset.xyz": null,
"trafficbroker.com": null,
"trafficstars.com": null,
"33traffic.com": null,
"lightson.vpsboard.com": null,
"bid.run": null,
"adcfrthyo.tk": null,
"hostingcloud.loan": null,
"affiliate.burn-out.tv": null,
"freewheel.mtgx.tv": null,
"admo.tv": null,
"adne.tv": null,
"video.oms.eu": null,
"cdnaz.win": null,
"hostingcloud.racing": null,
"analytics.blue": null,
"affiliates.vpn.ht": null,
"bridgetrack.com": null,
"cache.worldfriends.tv": null,
"nextlandingads.com": null,
"adrotate.se": null,
"microad.net": null,
"u-ad.info": null,
"optimize-stats.voxmedia.com": null,
"adfrog.info": null,
"adlinx.info": null,
"adalgo.info": null,
"affiliates.mozy.com": null,
"adwalte.info": null,
"adplans.info": null,
"adlerbo.info": null,
"partner.googleadservices.com": null,
"ininmacerad.pro": null,
"adm-vids.info": null,
"adproper.info": null,
"advsense.info": null,
"affiliates.mgmmirage.com": null,
"affiliates.goodvibes.com": null,
"affiliates.swappernet.com": null,
"performancetrack.info": null,
"affiliates.treasureisland.com": null,
"affiliates.londonmarketing.com": null,
"bannerexchange.com.au": null,
"advertisingvalue.info": null,
"ewxssoad.bid": null,
"ubertracking.info": null,
"adofuokjj.bid": null,
"loljuduad.bid": null,
"rqmlurpad.bid": null,
"mobitracker.info": null,
"adrtgbebgd.bid": null,
"scvonjdwad.bid": null,
"timonnbfad.bid": null,
"localytics.com": null,
"hostingcloud.faith": null,
"dstrack2.info": null,
"trackbar.info": null,
"dashbida.com": null,
"ad001.ru": null,
"admaster.net": null,
"ad.reachlocal.com": null,
"free-rewards.com-s.tv": null,
"clarium.global.ssl.fastly.net": null,
"affiliates.genealogybank.com": null,
"adnext.org": null,
"advertur.ru": null,
"advombat.ru": null,
"advertone.ru": null,
"chinagrad.ru": null,
"analytic.rocks": null,
"analytics.plex.tv": null,
"analytics.ifood.tv": null,
"toptracker.ru": null,
"volgograd-info.ru": null,
"deliberatelyvirtuallyshared.xyz": null,
"affiliate.resellerclub.com": null,
"totrack.ru": null,
"blogads.com": null,
"analytics.ettoredelnegro.pro": null,
"tracker.azet.sk": null,
"ftrack.ru": null,
"statistic.date": null,
"advnet.xyz": null,
"adzjzewsma.cf": null,
"adlure.biz": null,
"pix.speedbit.com": null,
"mtrack.nl": null,
"adz.zwee.ly": null,
"stat.radar.imgsmail.ru": null,
"clickpartoffon.xyz": null,
"analytics00.meride.tv": null,
"adsmws.cloudapp.net": null,
"cfcdist.loan": null,
"adbetclickin.pink": null,
"respond-adserver.cloudapp.net": null,
"skimresources.com": null,
"affiliateprogram.keywordspy.com": null,
"comscore.com": null,
"publicidad.net": null,
"tracker.revip.info": null,
"ads.cc": null,
"analytics.carambatv.ru": null,
"googlerank.info": null,
"ad.gt": null,
"cpaevent.ru": null,
"hostingcloud.bid": null,
"moevideo.net": null,
"trackingoffer.info": null,
"adlog.com.com": null,
"lead.im": null,
"livestats.la7.tv": null,
"tracking.vengovision.ru": null,
"adverts.itv.com": null,
"videos.oms.eu": null,
"affiliate.com": null,
"log.ren.tv": null,
"link.link.ru": null,
"fnro4yu0.loan": null,
"holexknw.loan": null,
"contextads.net": null,
"silverads.net": null,
"sevenads.net": null,
"ad.spielothek.so": null,
"zanox-affiliate.de": null,
"szzxtanwoptm.bid": null,
"clicktalecdn.sslcs.cdngc.net": null,
"wstats.e-wok.tv": null,
"tracker.tiu.ru": null,
"tracking.hostgator.com": null,
"drowadri.racing": null,
"analytics.cmg.net": null,
"screencapturewidget.aebn.net": null,
"analytic.pho.fm": null,
"adnow.com": null,
"img.bluehost.com": null,
"ihstats.cloudapp.net": null,
"googleadapis.l.google.com": null,
"log.worldsoft-cms.info": null,
"track.cooster.ru": null,
"xtracker.pro": null,
"cpufan.club": null,
"adnext.fr": null,
"microad.jp": null,
"post.rmbn.ru": null,
"hostingcloud.party": null,
"adserved.net": null,
"blogscash.info": null,
"hostingcloud.date": null,
"adfill.me": null,
"track.revolvermarketing.ru": null,
"analytics.wildtangent.com": null,
"nimiq.watch": null,
"textad.sexsearch.com": null,
"popads.media": null,
"metrics.aviasales.ru": null,
"adxxx.org": null,
"analytics.wetpaint.me": null,
"beacon.squixa.net": null,
"adnet.ru": null,
"bannerbank.ru": null,
"beacon.gutefrage.net": null,
"advmaker.su": null,
"webtrack.biz": null,
"analyzer.qmerce.com": null,
"adsnative.com": null,
"optimost.com": null,
"adboost.com": null,
"analytics.proxer.me": null,
"tracker2.apollo-mail.net": null,
"oas.luxweb.com": null,
"cdnfile.xyz": null,
"analytics.paddle.com": null,
"analytics.archive.org": null,
"livestats.matrix.it": null,
"ad-vice.biz": null,
"taeadsnmbbkvpw.bid": null,
"adten.eu": null,
"ad2adnetwork.biz": null,
"hostingcloud.stream": null,
"aimatch.com": null,
"stats.qmerce.com": null,
"count.yandeg.ru": null,
"sessioncam.com": null,
"sabin.free.fr": null,
"addynamics.eu": null,
"pixel.xmladfeed.com": null,
"cloudflare.solutions": null,
"jqwww.download": null,
"adxxx.me": null,
"profile.bharatmatrimony.com": null,
"buysellads.net": null,
"trackingapi.cloudapp.net": null,
"vologda-info.ru": null,
"jquery-uim.download": null,
"affiliates.myfax.com": null,
"engine.gamerati.net": null,
"spylog.ru": null,
"adcount.in": null,
"adnz.co": null,
"adro.co": null,
"experianmarketingservices.digital": null,
"pleasedontslaymy.download": null,
"access-analyze.org": null,
"analytics.epi.es": null,
"gandrad.org": null,
"porn-ad.org": null,
"awstrack.me": null,
"affiliates.galapartners.co.uk": null,
"layer-ad.org": null,
"analytics.iraiser.eu": null,
"metartmoney.met-art.com": null,
"stat.social": null,
"adigniter.org": null,
"advise.co": null,
"static.kinghost.com": null,
"zoomanalytics.co": null,
"adcarem.co": null,
"1e0y.xyz": null,
"hdat.xyz": null,
"hhit.xyz": null,
"analytics.rechtslupe.org": null,
"analytics.truecarbon.org": null,
"arpelog.info": null,
"adclear.net": null,
"hivps.xyz": null,
"avero.xyz": null,
"bh8yx.xyz": null,
"retag.xyz": null,
"bnbir.xyz": null,
"adpath.mobi": null,
"leadad.mobi": null,
"adwired.mobi": null,
"cndhit.xyz": null,
"verata.xyz": null,
"acamar.xyz": null,
"alamak.xyz": null,
"pcruxm.xyz": null,
"find-ip-address.org": null,
"visit.homepagle.com": null,
"oas.skyscanner.net": null,
"janrain.xyz": null,
"elwraek.xyz": null,
"fyredet.xyz": null,
"patoris.xyz": null,
"albireo.xyz": null,
"hit-pool.upscore.io": null,
"alemoney.xyz": null,
"proj2018.xyz": null,
"tidafors.xyz": null,
"checkapi.xyz": null,
"mp3toavi.xyz": null,
"permenor.xyz": null,
"zylstina.xyz": null,
"ficusoid.xyz": null,
"kxqvnfcg.xyz": null,
"aleinvest.xyz": null,
"quicktask.xyz": null,
"flac2flac.xyz": null,
"tchhelpdmn.xyz": null,
"zapstorage.xyz": null,
"analytics.gvim.mobi": null,
"tripedrated.xyz": null,
"alltheladyz.xyz": null,
"sniperlog.ru": null,
"adaction.se": null,
"powerad.ai": null,
"mataharirama.xyz": null,
"mobsoftffree.xyz": null,
"gripdownload.co": null,
"track.atom-data.io": null,
"cruftexcision.xyz": null,
"inspiringsweater.xyz": null,
"usenetnl.download": null,
"honestlypopularvary.xyz": null,
"privilegebedroomlate.xyz": null,
"traffic-media.co.uk": null,
"speee-ad.akamaized.net": null,
"stabilityappointdaily.xyz": null,
"pixel.watch": null,
"analytics.codigo.se": null,
"counter.gd": null,
"ad.duga.jp": null,
"advatar.to": null,
"tracking.vid4u.org": null,
"googleadservicepixel.com": null,
"analytics.mailmunch.co": null,
"track2.me": null,
"nicoad.nicovideo.jp": null,
"relead.com": null,
"affiliates.spark.net": null,
"cnstats.ru": null,
"adregain.ru": null,
"ad.idgtn.net": null,
"ad.jamba.net": null,
"adsjudo.com": null,
"torads.xyz": null,
"rlogoro.ru": null,
"advertise.com": null,
"manager.koocash.fr": null,
"beacon.mtgx.tv": null,
"optimalroi.info": null,
"ad.pickple.net": null,
"adserve.ph": null,
"affiliates.lynda.com": null,
"quantumws.net": null,
"monova.site": null,
"ad20.net": null,
"adv9.net": null,
"cnstats.cdev.eu": null,
"affiliates.minglematch.com": null,
"affiliates.picaboocorp.com": null,
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
"affiliates.franchisegator.com": null,
"ad-back.net": null,
"adgoi-1.net": null,
"adowner.net": null,
"bidhead.net": null,
"eads.to": null,
"hotlog.ru": null,
"warlog.ru": null,
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
"dfanalytics.dealerfire.com": null,
"individuad.net": null,
"addcontrol.net": null,
"adcastplus.net": null,
"adtransfer.net": null,
"adverticum.net": null,
"content-ad.net": null,
"widgetlead.net": null,
"ad-balancer.net": null,
"ad-delivery.net": null,
"dashboardad.net": null,
"analytics.reyrey.net": null,
"adimpression.net": null,
"adn.ebay.com": null,
"analytics.edgekey.net": null,
"analytics.traidnt.net": null,
"brand.net": null,
"admarketplace.net": null,
"stat.bilibili.tv": null,
"analytics.dvidshub.net": null,
"advertisingpath.net": null,
"adultcommercial.net": null,
"analytics.witglobal.net": null,
"adultadvertising.net": null,
"adinte.jp": null,
"aid-ad.jp": null,
"adnico.jp": null,
"i2ad.jp": null,
"advg.jp": null,
"admatrix.jp": null,
"impact-ad.jp": null,
"humanclick.com": null,
"clkads.com": null,
"hostingcloud.review": null,
"analytics.industriemagazin.net": null,
"xfast.host": null,
"objects.tremormedia.com": null,
"hostingcloud.download": null,
"eiadsdmj.bid": null,
"analytics.yola.net": null,
"logxp.ru": null,
"crazyad.net": null,
"admaya.in": null,
"admaza.in": null,
"adzmaza.in": null,
"pixel.reddit.com": null,
"adzincome.in": null,
"adchannels.in": null,
"analytic.piri.net": null,
"webts.adac.de": null,
"fairad.co": null,
"chartbeat.net": null,
"visitor-analytics.net": null,
"analytics.tio.ch": null,
"etracker.de": null,
"analytics.arz.at": null,
"tracking.thehut.net": null,
"tracking.ehavior.net": null,
"tracking.listhub.net": null,
"tracking.wlscripts.net": null,
"track.qcri.org": null,
"statistics.infowap.info": null,
"analytics.urx.io": null,
"advmaker.ru": null,
"analytics.solidbau.at": null,
"ad.kissanime.io": null,
"track.kandle.org": null,
"ad-apac.doubleclick.net": null,
"ad-emea.doubleclick.net": null,
"adtr.io": null,
"affiliates.thrixxx.com": null,
"stats.teledyski.info": null,
"cdn.trafficexchangelist.com": null,
"deals.buxr.net": null,
"adless.io": null,
"adapex.io": null,
"adlive.io": null,
"adnami.io": null,
"analytics.suggestv.io": null,
"ad.kisscartoon.io": null,
"adverti.io": null,
"analyticapi.pho.fm": null,
"logz.ru": null,
"webads.co.nz": null,
"knowlead.io": null,
"affiliates.bookdepository.com": null,
"adtotal.pl": null,
"clcknads.pro": null,
"adalliance.io": null,
"adexchange.io": null,
"landsraad.cc": null,
"content-offer-app.site": null,
"performanceanalyser.net": null,
"event.getblue.io": null,
"trackingoffer.net": null,
"internalredirect.site": null,
"promotools.biz": null,
"softonic-analytics.net": null,
"userlog.synapseip.tv": null,
"tracker2kss.eu": null,
"trackerodss.eu": null,
"adultsense.org": null,
"k9anf8bc.webcam": null,
"gitcdn.site": null,
"analytics-engine.net": null,
"redirections.site": null,
"tracking.oe24.at": null,
"adplusplus.fr": null,
"fasttracktech.biz": null,
"tracking.krone.at": null,
"tracking.novem.pl": null,
"admeira.ch": null,
"cookies.reedbusiness.nl": null,
"etology.com": null,
"tracking.kurier.at": null,
"scoutanalytics.net": null,
"nativeads.com": null,
"logger.su": null,
"monkeytracker.cz": null,
"beacon.nuskin.com": null,
"img.servint.net": null,
"tkn.4tube.com": null,
"beacon.tingyun.com": null,
"beacon.viewlift.com": null,
"simpleanalytics.io": null,
"beacon.riskified.com": null,
"freetracker.biz": null,
"adregain.com": null,
"tracking.customerly.io": null,
"beacon.errorception.com": null,
"beacon.heliumnetwork.com": null,
"beacon.securestudies.com": null,
"hs-analytics.net": null,
"yandex-metrica.ru": null,
"beacon.wikia-services.com": null,
"video-ad-stats.googlesyndication.com": null,
"qom006.site": null,
"tags.cdn.circlesix.co": null,
"track.bluecompany.cl": null,
"sageanalyst.net": null,
"analyticsip.net": null,
"owlanalytics.io": null,
"eroticmix.blogspot.": null,
"accede.site": null,
"affiliate.godaddy.com": null,
"trackpath.biz": null,
"hitcount.dk": null,
"tracker.mtrax.net": null,
"etracker.com": null,
"analytics.carambo.la": null,
"ker.pic2pic.site": null,
"epnt.ebay.com": null,
"lapi.ebay.com": null,
"tracker.publico.pt": null,
"analytics.websolute.it": null,
"analytics.digitouch.it": null,
"images.criteo.net": null,
"ilapi.ebay.com": null,
"count.rin.ru": null,
"advertica.ae": null,
"timeslogtn.timesnow.tv": null,
"visitor-analytics.io": null,
"stats.mos.ru": null,
"trackword.net": null,
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
"utrack.hexun.com": null,
"iptrack.biz": null,
"stats.lifenews.ru": null,
"metrics.tbliab.net": null,
"track.g-bot.net": null,
"torads.me": null,
"buysellads.com": null,
"socialtrack.co": null,
"analytics-static.ugc.bazaarvoice.com": null,
"counter.insales.ru": null,
"metrics.ctvdigital.net": null,
"webads.nl": null,
"letsgoshopping.tk": null,
"visits.lt": null,
"track.redirecting2.net": null,
"vihtori-analytics.fi": null,
"socialtrack.net": null,
"analytics.matchbin.com": null,
"spinbox.freedom.com": null,
"adclick.pk": null,
"webtracker.jp": null,
"minexmr.stream": null,
"ad.cooks.com": null,
"ad.evozi.com": null,
"private.camz.": null,
"tracker.euroweb.net": null,
"mediatraffic.com": null,
"tracking.trovaprezzi.it": null,
"webstat.no": null,
"webstat.net": null,
"tracking.conversionlab.it": null,
"ad.fnnews.com": null,
"speee-ad.jp": null,
"tracking.conversion-lab.it": null,
"tracker.streamroot.io": null,
"stat.ruvr.ru": null,
"bb-analytics.jp": null,
"adsrv.us": null,
"counter.webmasters.bpath.com": null,
"stat.tvigle.ru": null,
"ad.icasthq.com": null,
"ad.vidaroo.com": null,
"ad.jamster.com": null,
"abbeyblog.me": null,
"hodlers.party": null,
"stat.sputnik.ru": null,
"stat.pravmir.ru": null,
"livestats.fr": null,
"stat.pladform.ru": null,
"business.sharedcount.com": null,
"analytics-cms.whitebeard.me": null,
"adku.co": null,
"omoukkkj.stream": null,
"goredirect.party": null,
"onlinereserchstatistics.online": null,
"stat.woman-announce.ru": null,
"analytics.rambla.be": null,
"xvideosharing.site": null,
"analytics.belgacom.be": null,
"sponsoredby.me": null,
"moneroocean.stream": null,
"webassembly.stream": null,
"clkdown.info": null,
"coinhive-proxy.party": null,
"windowne.info": null,
"ad.outsidehub.com": null,
"ad.reklamport.com": null,
"ad.lyricswire.com": null,
"video1404.info": null,
"intelensafrete.stream": null,
"klapenlyidveln.stream": null,
"analysis.focalprice.com": null,
"expresided.info": null,
"ad.foxnetworks.com": null,
"solutionzip.info": null,
"locotrack.net": null,
"track.derbund.ch": null,
"downlossinen.info": null,
"track.cordial.io": null,
"track.codepen.io": null,
"ad.directmirror.com": null,
"track.24heures.ch": null,
"track.mobicast.io": null,
"contentdigital.info": null,
"ad.mesomorphosis.com": null,
"ad.theepochtimes.com": null,
"impressioncontent.info": null,
"seecontentdelivery.info": null,
"webcontentdelivery.info": null,
"zumcontentdelivery.info": null,
"smartoffer.site": null,
"carbonads.com": null,
"inewcontentdelivery.info": null,
"requiredcollectfilm.info": null,
"track.bernerzeitung.ch": null,
"affiligay.net": null,
"googleme.eu": null,
"ad.iloveinterracial.com": null,
"tracking.to": null,
"log.idnes.cz": null,
"adsummos.net": null,
"tjblfqwtdatag.bid": null,
"w4statistics.info": null,
"affil.mupromo.com": null,
"analytics.rtbf.be": null,
"beacon.aimtell.com": null,
"sessions.exchange": null,
"affiliate.cx": null,
"filadmir.site": null,
"gctwh9xc.site": null,
"itempana.site": null,
"jfx61qca.site": null,
"less-css.site": null,
"1wzfew7a.site": null,
"ag2hqdyt.site": null,
"adip.ly": null,
"tracking.ustream.tv": null,
"bitx.tv": null,
"laim.tv": null,
"stattds.club": null,
"tracker.calameo.com": null,
"htl.bid": null,
"adgoi.mobi": null,
"webstat.se": null,
"stats.propublica.org": null,
"ijncw.tv": null,
"dawin.tv": null,
"affec.tv": null,
"e2yth.tv": null,
"ov8pc.tv": null,
"google-rank.org": null,
"infinity-tracking.net": null,
"trackstarsengland.net": null,
"nedstat.net": null,
"extend.tv": null,
"trackadvertising.net": null,
"log.mappy.net": null,
"adserve.com": null,
"zaehler.tv": null,
"shoofle.tv": null,
"trackmkxoffers.se": null,
"exponderle.pro": null,
"log.nordot.jp": null,
"ad.style": null,
"dom002.site": null,
"viedeo2k.tv": null,
"hostingcloud.win": null,
"hemnes.win": null,
"mutuza.win": null,
"trackdiscovery.net": null,
"trackpromotion.net": null,
"bitfalcon.tv": null,
"liwimgti.bid": null,
"promotiontrack.mobi": null,
"visistat.com": null,
"netcounter.de": null,
"g-content.bid": null,
"eimgxlsqj.bid": null,
"filenlgic.bid": null,
"fjmxpixte.bid": null,
"nativeroll.tv": null,
"depilflash.tv": null,
"directchat.tv": null,
"hashing.win": null,
"proofly.win": null,
"bcoavtimgn.bid": null,
"feacamnliz.bid": null,
"ghizipjlsi.bid": null,
"skytvonline.tv": null,
"tracetracking.net": null,
"air360tracker.net": null,
"avazutracking.net": null,
"axbpixbcucv.bid": null,
"valueclick.net": null,
"fxox4wvv.win": null,
"checkmy.cam": null,
"arqxpopcywrr.bid": null,
"bjkookfanmxx.bid": null,
"nrwofsfancse.bid": null,
"pmzktktfanzem.bid": null,
"yxwdppixvzxau.bid": null,
"tracking.tchibo.de": null,
"beead.net": null,
"analoganalytics.com": null,
"trackonomics.net": null,
"tracking.hrs.de": null,
"tracking.srv2.de": null,
"adorika.net": null,
"adlure.net": null,
"tracking.linda.de": null,
"lindon-pool.win": null,
"swiftmining.win": null,
"tracking.plinga.de": null,
"tracking.ladies.de": null,
"tracking.sport1.de": null,
"host-go.info": null,
"track.veedio.it": null,
"sponsorselect.com": null,
"tracking.mvsuite.de": null,
"tracking.netbank.de": null,
"opentracker.net": null,
"ppctracking.net": null,
"smartracker.net": null,
"trackedlink.net": null,
"roitracking.net": null,
"adku.com": null,
"tracking.emsmobile.de": null,
"mp.pianomedia.eu": null,
"tracking.promiflash.de": null,
"adbit.biz": null,
"adnet.biz": null,
"tracking.hannoversche.de": null,
"analytics.ladmedia.fr": null,
"event-listener.air.tv": null,
"track.cedsdigital.it": null,
"realclick.co.kr": null,
"e-webtrack.net": null,
"maxtracker.net": null,
"trackedweb.net": null,
"trackmyweb.net": null,
"tracking.gj-mobile-services.de": null,
"tracking.beilagen-prospekte.de": null,
"rotaban.ru": null,
"gameads.com": null,
"cashtrafic.info": null,
"hostip.info": null,
"brandads.net": null,
"ad.spreaker.com": null,
"metric.inetcore.com": null,
"mstracker.net": null,
"track-web.net": null,
"wisetrack.net": null,
"event.dkb.de": null,
"analytics.competitoor.com": null,
"jumplead.com": null,
"trackword.biz": null,
"tracking.autoscout24.com": null,
"track.parse.ly": null,
"track.sauce.ly": null,
"trackcmp.net": null,
"tracktrk.net": null,
"zmctrack.net": null,
"counter.nn.ru": null,
"silverpop.com": null,
"arcadebannerexchange.org": null,
"analytics.vendemore.com": null,
"analytics.grupogodo.com": null,
"analytics.sportybet.com": null,
"analytics.teespring.com": null,
"analytics.volvocars.com": null,
"analytics.audioeye.com": null,
"analytics.hpprintx.com": null,
"analytics.orenshmu.com": null,
"analytics.freespee.com": null,
"analytics.mindjolt.com": null,
"analytics.upworthy.com": null,
"analytics.closealert.com": null,
"analytics.groupe-seb.com": null,
"analytics.snidigital.com": null,
"analytics.linkwelove.com": null,
"analytics.traderlink.com": null,
"analytics.themarketiq.com": null,
"analytics.schoolwires.com": null,
"analytics.socialblade.com": null,
"analytics.whatculture.com": null,
"analytics.artirix.com": null,
"analytics.cincopa.com": null,
"analytics.pinpoll.com": null,
"analytics.thenest.com": null,
"analytics.infobae.com": null,
"analytics.atomiconline.com": null,
"analytics.cohesionapps.com": null,
"analytics.conmio.com": null,
"analytics.kapost.com": null,
"analytics.piksel.com": null,
"analytics.prezly.com": null,
"analytics.aasaam.com": null,
"analytics.jabong.com": null,
"analytics.posttv.com": null,
"analytics.thetab.com": null,
"analytics.zg-api.com": null,
"analytics.midwesternmac.com": null,
"analytics.vanillaforums.com": null,
"analytics.ziftsolutions.com": null,
"analytics.apnewsregistry.com": null,
"analytics.hindustantimes.com": null,
"analytics.favcy.com": null,
"analytics.revee.com": null,
"analytics.brave.com": null,
"analytics.convertlanguage.com": null,
"analytics.21cn.com": null,
"analytics.onlyonlinemarketing.com": null,
"analytics.strangeloopnetworks.com": null,
"analytics.disneyinternational.com": null,
"analytics.30m.com": null,
"analytics.r17.com": null,
"vacroz.xyz": null,
"counter.amik.ru": null,
"counter.rian.ru": null,
"counter.pr-cy.ru": null,
"addlvr.com": null,
"jstracker.com": null,
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
var bad_da_host_RegExp = /^(?:[\w-]+\.)*?(?:analytics\-beacon\-(?=([\s\S]*?\.amazonaws\.com))\1|rcm(?=([\s\S]*?\.amazon\.))\2|images\.(?=([\s\S]*?\.criteo\.net))\3)/i;
var bad_da_host_regex_flag = 3 > 0 ? true : false;  // test for non-zero number of rules

// 287 rules:
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
"cloudfront.net/scripts/js3caf.js": null,
"codecguide.com/stats.js": null,
"myway.com/gca_iframe.html": null,
"wheninmanila.com/wp-content/uploads/2012/12/Marie-France-Buy-1-Take-1-Deal-Discount-WhenInManila.jpg": null,
"eastmoney.com/counter.js": null,
"elb.amazonaws.com/small.gif": null,
"eageweb.com/stats.php": null,
"allmyvideos.net/player/ova-jw.swf": null,
"thefile.me/apu.php": null,
"turboimagehost.com/p1.js": null,
"wired.com/tracker.js": null,
"dpstatic.com/banner.png": null,
"cgmlab.com/tools/geotarget/custombanner.js": null,
"brightcove.com/1pix.gif": null,
"googletagservices.com/dcm/dcmads.js": null,
"skyrock.net/js/stats_blog.js": null,
"barclaycard.co.uk/cs/static/js/esurveys/esurveys.js": null,
"piano-media.com/bucket/novosense.swf": null,
"washingtonpost.com/rw/sites/twpweb/js/init/init.track-header-1.0.0.js": null,
"websitehome.co.uk/seoheap/cheap-web-hosting.gif": null,
"mercola.com/Assets/js/omniture/sitecatalyst/mercola_s_code.js": null,
"cafenews.pl/mpl/static/static.js": null,
"ulogin.ru/js/stats.js": null,
"video44.net/gogo/yume-h.swf": null,
"csmonitor.com/extension/csm_base/design/standard/javascript/adobe/s_code.js": null,
"ge.com/sites/all/themes/ge_2012/assets/js/bin/s_code.js": null,
"s-msn.com/s/js/loader/activity/trackloader.min.js": null,
"vodo.net/static/images/promotion/utorrent_plus_buy.png": null,
"blogsdna.com/wp-content/themes/blogsdna2011/images/advertisments.png": null,
"playstation.com/pscomauth/groups/public/documents/webasset/community_secured_s_code.js": null,
"charter.com/static/scripts/mock/tracking.js": null,
"hitleap.com/assets/banner.png": null,
"revisionworld.co.uk/sites/default/files/imce/Double-MPU2-v2.gif": null,
"zylom.com/pixel.jsp": null,
"snazzyspace.com/generators/viewer-counter/counter.php": null,
"wheninmanila.com/wp-content/uploads/2014/02/DTC-Hardcore-Quadcore-300x100.gif": null,
"webhostranking.com/images/bluehost-coupon-banner-1.gif": null,
"cloudfront.net/scripts/cookies.js": null,
"tubepornclassic.com/js/111.js": null,
"wheninmanila.com/wp-content/uploads/2011/05/Benchmark-Email-Free-Signup.gif": null,
"csmonitor.com/extension/csm_base/design/csm_design/javascript/omniture/s_code.js": null,
"thumblogger.com/thumblog/top_banner_silver.js": null,
"nitrobahn.com.s3.amazonaws.com/theme/getclickybadge.gif": null,
"nzbking.com/static/nzbdrive_banner.swf": null,
"fncstatic.com/static/all/js/geo.js": null,
"adimgs.t2b.click/assets/js/ttbir.js": null,
"military.com/data/popup/new_education_popunder.htm": null,
"9msn.com.au/share/com/js/fb_google_intercept.js": null,
"watchuseek.com/site/forabar/zixenflashwatch.swf": null,
"forms.aweber.com/form/styled_popovers_and_lightboxes.js": null,
"phonearena.com/_track.php": null,
"aeroplan.com/static/js/omniture/s_code_prod.js": null,
"gannett-cdn.com/appservices/partner/sourcepoint/sp-mms-client.js": null,
"aircanada.com/shared/common/sitecatalyst/s_code.js": null,
"adap.tv/redir/client/static/as3adplayer.swf": null,
"yourtv.com.au/share/com/js/fb_google_intercept.js": null,
"hotdeals360.com/static/js/kpwidgetweb.js": null,
"baymirror.com/static/img/bar.gif": null,
"wheninmanila.com/wp-content/uploads/2014/04/zion-wifi-social-hotspot-system.png": null,
"pimpandhost.com/static/html/iframe.html": null,
"expressen.se/static/scripts/s_code.js": null,
"sexvideogif.com/msn.js": null,
"dl-protect.com/pop.js": null,
"jeuxvideo.com/contenu/medias/video/countv.php": null,
"liveonlinetv247.com/images/muvixx-150x50-watch-now-in-hd-play-btn.gif": null,
"sexier.com/services/adsredirect.ashx": null,
"dexerto.com/app/uploads/2016/11/Gfuel-LemoNade.jpg": null,
"audiusa.com/us/brand/en.usertracking_javascript.js": null,
"ultimatewindowssecurity.com/securitylog/encyclopedia/images/allpartners.swf": null,
"naptol.com/usr/local/csp/staticContent/js/ga.js": null,
"paypal.com/acquisition-app/static/js/s_code.js": null,
"soe.com/js/web-platform/web-data-tracker.js": null,
"libertyblitzkrieg.com/wp-content/uploads/2012/09/cc200x300.gif": null,
"btkitty.org/static/images/880X60.gif": null,
"privacytool.org/AnonymityChecker/js/fontdetect.js": null,
"attorrents.com/static/images/download3.png": null,
"cdnplanet.com/static/rum/rum.js": null,
"saabsunited.com/wp-content/uploads/REALCAR-SAABSUNITED-5SEC.gif": null,
"skyrock.net/img/pix.gif": null,
"btkitty.com/static/images/880X60.gif": null,
"emergencymedicalparamedic.com/wp-content/uploads/2011/12/anatomy.gif": null,
"ultimatewindowssecurity.com/images/banner80x490_WSUS_FreeTool.jpg": null,
"staticbucket.com/boost//Scripts/libs/flickity.js": null,
"vidyoda.com/fambaa/chnls/ADSgmts.ashx": null,
"amazonaws.com/pmb-musics/download_itunes.png": null,
"cloudfront.net/track.html": null,
"shopping.com/sc/pac/sdc_widget_v2.0_proxy.js": null,
"tpb.piraten.lu/static/img/bar.gif": null,
"better-explorer.com/wp-content/uploads/2012/09/credits.png": null,
"watchuseek.com/media/longines_legenddiver.gif": null,
"better-explorer.com/wp-content/uploads/2013/07/hf.5.png": null,
"johnbridge.com/vbulletin/images/tyw/cdlogo-john-bridge.jpg": null,
"careerwebsite.com/distrib_pages/jobs.cfm": null,
"downloadsmais.com/imagens/download-direto.gif": null,
"razor.tv/site/servlet/tracker.jsp": null,
"whatreallyhappened.com/webpageimages/banners/uwslogosm.jpg": null,
"lexus.com/lexus-share/js/campaign_tracking.js": null,
"crabcut.net/popup.js": null,
"quintcareers.4jobs.com/Common/JavaScript/functions.tracking.js": null,
"lightboxcdn.com/static/identity.html": null,
"androidfilehost.com/libs/otf/stats.otf.php": null,
"ebizmbainc.netdna-cdn.com/images/tab_sponsors.gif": null,
"mnginteractive.com/live/js/omniture/SiteCatalystCode_H_22_1_NC.js": null,
"nih.gov/share/scripts/survey.js": null,
"static.pes-serbia.com/prijatelji/zero.png": null,
"livetradingnews.com/wp-content/uploads/vamp_cigarettes.png": null,
"shopify.com/track.js": null,
"investegate.co.uk/Weblogs/IGLog.aspx": null,
"fileplanet.com/fileblog/sub-no-ad.shtml": null,
"whitedolly.com/wcf/images/redbar/logo_neu.gif": null,
"themag.co.uk/assets/BV200x90TOPBANNER.png": null,
"desiretoinspire.net/storage/layout/royalcountessad.gif": null,
"ibtimes.com/player/stats.swf": null,
"watchseries.eu/images/download.png": null,
"technewsdaily.com/crime-stats/local_crime_stats.php": null,
"sexilation.com/wp-content/uploads/2013/01/Untitled-1.jpg": null,
"imageteam.org/upload/big/2014/06/22/53a7181b378cb.png": null,
"addtoany.com/menu/transparent.gif": null,
"taringa.net/ajax/track-visit.php": null,
"xbox-scene.com/crave/logo_on_white_s160.jpg": null,
"streams.tv/js/bn5.js": null,
"healthcarejobsite.com/Common/JavaScript/functions.tracking.js": null,
"flashi.tv/histats.php": null,
"ino.com/img/sites/mkt/click.gif": null,
"meanjin.com.au/static/images/sponsors.jpg": null,
"webtutoriaux.com/services/compteur-visiteurs/index.php": null,
"images.military.com/pixel.gif": null,
"youwatch.org/vod-str.html": null,
"hostingtoolbox.com/bin/Count.cgi": null,
"jillianmichaels.com/images/publicsite/advertisingslug.gif": null,
"saabsunited.com/wp-content/uploads/rbm21.jpg": null,
"saabsunited.com/wp-content/uploads/USACANADA.jpg": null,
"pimpandhost.com/images/pah-download.gif": null,
"microsoft.com/getsilverlight/scripts/silverlight/SilverlightAtlas-MSCOM-Tracking.js": null,
"arstechnica.com/dragons/breath.gif": null,
"jappy.tv/i/wrbng/abb.png": null,
"imgdino.com/gsmpop.js": null,
"cardstore.com/affiliate.jsp": null,
"domainapps.com/assets/img/domain-apps.gif": null,
"myanimelist.net/static/logging.html": null,
"friday-ad.co.uk/endeca/afccontainer.aspx": null,
"ewrc-results.com/images/horni_ewrc_result_banner3.jpg": null,
"webmd.com/dtmcms/live/webmd/PageBuilder_Assets/JS/oas35.js": null,
"worldnow.com/global/tools/video/Namespace_VideoReporting_DW.js": null,
"zipcode.org/site_images/flash/zip_v.swf": null,
"uploadshub.com/downloadfiles/download-button-blue.gif": null,
"shareit.com/affiliate.html": null,
"cruisesalefinder.co.nz/affiliates.html": null,
"ibrod.tv/ib.php": null,
"washingtonpost.com/wp-srv/javascript/piggy-back-on-ads.js": null,
"samsung.com/ph/nextisnow/files/javascript.js": null,
"cams.com/p/cams/cpcs/streaminfo.cgi": null,
"statig.com.br/pub/setCookie.js": null,
"videobull.to/wp-content/themes/videozoom/images/gotowatchnow.png": null,
"picturevip.com/imagehost/top_banners.html": null,
"cbc.ca/video/bigbox.html": null,
"greyorgray.com/images/Fast%20Business%20Loans%20Ad.jpg": null,
"watchuseek.com/media/clerc-final.jpg": null,
"nbcudigitaladops.com/hosted/housepix.gif": null,
"mywot.net/files/wotcert/vipre.png": null,
"pcgamesn.com/sites/default/files/SE4L.JPG": null,
"qbn.com/media/static/js/ga.js": null,
"youwatch.org/driba.html": null,
"youwatch.org/9elawi.html": null,
"youwatch.org/iframe1.html": null,
"messianictimes.com/images/Jews%20for%20Jesus%20Banner.png": null,
"syndication.visualthesaurus.com/std/vtad.js": null,
"videoszoofiliahd.com/wp-content/themes/vz/js/p.js": null,
"sofascore.com/geoip.js": null,
"static.tumblr.com/dhqhfum/WgAn39721/cfh_header_banner_v2.jpg": null,
"google-analytics.com/siteopt.js": null,
"gold-prices.biz/gold_trading_leader.gif": null,
"devilgirls.co/images/devil.gif": null,
"wearetennis.com/img/common/bnp-logo.png": null,
"judgeporn.com/video_pop.php": null,
"englishgrammar.org/images/30off-coupon.png": null,
"kau.li/yad.js": null,
"watchuseek.com/media/wus-image.jpg": null,
"kuiken.co/static/w.js": null,
"rtlradio.lu/stats.php": null,
"pcgamesn.com/sites/default/files/Se4S.jpg": null,
"desiretoinspire.net/storage/layout/modmaxbanner.gif": null,
"lazygirls.info/click.php": null,
"letour.fr/img/v6/sprite_partners_2x.png": null,
"as.jivox.com/jivox/serverapis/getcampaignbysite.php": null,
"nih.gov/medlineplus/images/mplus_en_survey.js": null,
"google-analytics.com/cx/api.js": null,
"staticice.com.au/cgi-bin/stats.cgi": null,
"lijit.com/adif_px.php": null,
"better-explorer.com/wp-content/uploads/2013/10/PoweredByNDepend.png": null,
"playomat.de/sfye_noscript.php": null,
"makeagif.com/parts/fiframe.php": null,
"videobull.to/wp-content/themes/videozoom/images/stream-hd-button.gif": null,
"releaselog.net/uploads2/656d7eca2b5dd8f0fbd4196e4d0a2b40.jpg": null,
"scientopia.org/public_html/clr_lympholyte_banner.gif": null,
"rednationonline.ca/Portals/0/derbystar_leaderboard.jpg": null,
"ablacrack.com/popup-pvd.js": null,
"russellgrant.com/hostedsearch/panelcounter.aspx": null,
"fileom.com/img/downloadnow.png": null,
"watchop.com/player/watchonepiece-gao-gamebox.swf": null,
"publicdomaintorrents.info/srsbanner.gif": null,
"klm.com/travel/generic/static/js/measure_async.js": null,
"js.static.m1905.cn/pingd.js": null,
"24hourfitness.com/includes/script/siteTracking.js": null,
"file.org/fo/scripts/download_helpopt.js": null,
"uramov.info/wav/wavideo.html": null,
"bongacash.com/tools/promo.php": null,
"johnbridge.com/vbulletin/images/tyw/wedi-shower-systems-solutions.png": null,
"washtimes.com/static/images/SelectAutoWeather_v2.gif": null,
"thevideo.me/mba/cds.js": null,
"serial.sw.cracks.me.uk/img/logo.gif": null,
"odnaknopka.ru/stat.js": null,
"watchfree.to/topright.php": null,
"hwbot.org/banner.img": null,
"kleisauke.nl/static/img/bar.gif": null,
"alladultnetwork.tv/main/videoadroll.xml": null,
"unblockedpiratebay.com/static/img/bar.gif": null,
"publicdomaintorrents.info/grabs/hdsale.png": null,
"tubeplus.me/resources/js/codec.js": null,
"forward.com/workspace/assets/newimages/amazon.png": null,
"prospects.ac.uk/assets/js/prospectsWebTrends.js": null,
"virginholidays.co.uk/_assets/js/dc_storm/track.js": null,
"momtastic.com/libraries/pebblebed/js/pb.track.js": null,
"timesnow.tv/googlehome.cms": null,
"vbs.tv/tracker.html": null,
"watchseries.eu/js/csspopup.js": null,
"swatchseries.to/bootstrap.min.js": null,
"jivox.com/jivox/serverapis/getcampaignbyid.php": null,
"digitizor.com/wp-content/digimages/xsoftspyse.png": null,
"merchantcircle.com/static/track.js": null,
"redtube.com/_status/pix.php": null,
"mercuryinsurance.com/static/js/s_code.js": null,
"witbankspurs.co.za/layout_images/sponsor.jpg": null,
"kitguru.net/wp-content/wrap.jpg": null,
"paper.li/javascripts/analytics.js": null,
"euronews.com/media/farnborough/farnborough_wp.jpg": null,
"24video.net/din_new6.php": null,
"fujifilm.com/js/shared/analyzer.js": null,
"fantasti.cc/ajax/gw.php": null,
"atom-data.io/session/latest/track.html": null,
"netdna-ssl.com/wp-content/uploads/2017/01/tla17janE.gif": null,
"netdna-ssl.com/wp-content/uploads/2017/01/tla17sepB.gif": null,
"cclickvidservgs.com/mattel/cclick.js": null,
"ltfm.ca/stats.php": null,
"rightmove.co.uk/ps/images/logging/timer.gif": null,
"cash9.org/assets/img/banner2.gif": null,
"oscars.org/scripts/wt_include1.js": null,
"oscars.org/scripts/wt_include2.js": null,
"bc.vc/adbcvc.html": null,
"filestream.me/requirements/images/cialis_generic.gif": null,
"live-medias.net/button.php": null,
"script.idgentertainment.de/gt.js": null,
"amazonaws.com/accio-lib/accip_script.js": null,
"checker.openwebtorrent.com/digital-ocean.jpg": null,
"experiandirect.com/javascripts/tracking.js": null,
"trutv.com/includes/mods/iframes/mgid-blog.php": null,
"twinsporn.net/images/free-penis-pills.png": null,
"piano-media.com/auth/index.php": null,
"monkeyquest.com/monkeyquest/static/js/ga.js": null };
var bad_da_hostpath_exact_flag = 287 > 0 ? true : false;  // test for non-zero number of rules
    
// 930 rules as an efficient NFA RegExp:
var bad_da_hostpath_RegExp = /^(?:[\w-]+\.)*?(?:doubleclick\.net\/adx\/|doubleclick\.net\/adj\/|piano\-media\.com\/uid\/|jobthread\.com\/t\/|pornfanplace\.com\/js\/pops\.|porntube\.com\/adb\/|quantserve\.com\/pixel\/|doubleclick\.net\/pixel|addthiscdn\.com\/live\/|baidu\.com\/pixel|doubleclick\.net\/ad\/|netdna\-ssl\.com\/tracker\/|adf\.ly\/_|imageshack\.us\/ads\/|firedrive\.com\/tools\/|freakshare\.com\/banner\/|adform\.net\/banners\/|amazonaws\.com\/analytics\.|adultfriendfinder\.com\/banners\/|baidu\.com\/ecom|facebook\.com\/tr|widgetserver\.com\/metrics\/|google\-analytics\.com\/plugins\/|veeseo\.com\/tracking\/|channel4\.com\/ad\/|chaturbate\.com\/affiliates\/|redtube\.com\/stats\/|barnebys\.com\/widgets\/|sextronix\.com\/images\/|domaintools\.com\/partners\/|google\.com\/analytics\/|view\.atdmt\.com\/partner\/|adultfriendfinder\.com\/javascript\/|yahoo\.com\/track\/|cloudfront\.net\/track|yahoo\.com\/beacon\/|4tube\.com\/iframe\/|visiblemeasures\.com\/log|cursecdn\.com\/banner\/|pop6\.com\/banners\/|google\-analytics\.com\/gtm\/js|pcwdld\.com\/wp\-content\/plugins\/wbounce\/|propelplus\.com\/track\/|wupload\.com\/referral\/|dditscdn\.com\/log\/|adultfriendfinder\.com\/go\/|mediaplex\.com\/ad\/js\/|xvideos\-free\.com\/d\/|wtprn\.com\/sponsors\/|imagetwist\.com\/banner\/|github\.com\/_stats|slashgear\.com\/stats\/|photobucket\.com\/track\/|wired\.com\/event|sex\.com\/popunder\/|hothardware\.com\/stats\/|siberiantimes\.com\/counter\/|healthtrader\.com\/banner\-|voyeurhit\.com\/contents\/content_sources\/|pornoid\.com\/contents\/content_sources\/|xxxhdd\.com\/contents\/content_sources\/|lovefilm\.com\/partners\/|topbucks\.com\/popunder\/|broadbandgenie\.co\.uk\/widget|xxvideo\.us\/ad728x15|powvideo\.net\/ban\/|livedoor\.com\/counter\/|soufun\.com\/stats\/|pornalized\.com\/contents\/content_sources\/|primevideo\.com\/uedata\/|vodpod\.com\/stats\/|video\-cdn\.abcnews\.com\/ad_|zawya\.com\/ads\/|shareasale\.com\/image\/|msn\.com\/tracker\/|cnn\.com\/ad\-|baidu\.com\/billboard\/pushlog\/|soundcloud\.com\/event|fapality\.com\/contents\/content_sources\/|appspot\.com\/stats|rapidgator\.net\/images\/pics\/|fwmrm\.net\/ad\/|hstpnetwork\.com\/ads\/|static\.criteo\.net\/js\/duplo[^\w.%-]|sawlive\.tv\/ad|sourceforge\.net\/log\/|videowood\.tv\/ads|adroll\.com\/pixel\/|conduit\.com\/\/banners\/|ad\.admitad\.com\/banner\/|googlesyndication\.com\/sodar\/|googlesyndication\.com\/safeframe\/|secureupload\.eu\/banners\/|daylogs\.com\/counter\/|hosting24\.com\/images\/banners\/|sparklit\.com\/counter\/|phncdn\.com\/iframe|red\-tube\.com\/popunder\/|gamestar\.de\/_misc\/tracking\/|chameleon\.ad\/banner\/|videoplaza\.tv\/proxy\/tracker[^\w.%-]|nytimes\.com\/ads\/|twitter\.com\/i\/jot|spacash\.com\/popup\/|filecrypt\.cc\/p\.|liutilities\.com\/partners\/|addthis\.com\/live\/|pan\.baidu\.com\/api\/analytics|youtube\.com\/pagead\/|doubleclick\.net\/pfadx\/video\.marketwatch\.com\/|girlfriendvideos\.com\/ad|vidzi\.tv\/mp4|keepvid\.com\/ads\/|ad\.atdmt\.com\/s\/|static\.criteo\.net\/images[^\w.%-]|citygridmedia\.com\/ads\/|theporncore\.com\/contents\/content_sources\/|chaturbate\.com\/creative\/|twitter\.com\/metrics|worldfree4u\.top\/banners\/|dailymotion\.com\/track\-|dailymotion\.com\/track\/|shareaholic\.com\/analytics_|kqzyfj\.com\/image\-|jdoqocy\.com\/image\-|tkqlhce\.com\/image\-|ad\.doubleclick\.net\/ddm\/trackclk\/|anysex\.com\/assets\/|cfake\.com\/images\/a\/|ad\.atdmt\.com\/e\/|hqq\.tv\/js\/betterj\/|trrsf\.com\/metrics\/|virool\.com\/widgets\/|advfn\.com\/tf_|mygaming\.co\.za\/news\/wp\-content\/wallpapers\/|ad\.admitad\.com\/fbanner\/|xhamster\.com\/ads\/|quora\.com\/_\/ad\/|mochiads\.com\/srv\/|ad\.atdmt\.com\/i\/img\/|reevoo\.com\/track\/|howtogermany\.com\/banner\/|aliexpress\.com\/js\/beacon_|pornmaturetube\.com\/content\/|tube18\.sex\/tube18\.|doubleclick\.net\/pfadx\/ugo\.gv\.1up\/|livefyre\.com\/tracking\/|carbiz\.in\/affiliates\-and\-partners\/|videoplaza\.com\/proxy\/distributor\/|static\.criteo\.com\/flash[^\w.%-]|sun\.com\/share\/metrics\/|rt\.com\/static\/img\/banners\/|static\.criteo\.com\/images[^\w.%-]|andyhoppe\.com\/count\/|video\.mediaset\.it\/polymediashowanalytics\/|ad\.mo\.doubleclick\.net\/dartproxy\/|autotrader\.co\.za\/partners\/|fulltiltpoker\.com\/affiliates\/|mtvnservices\.com\/metrics\/|questionmarket\.com\/static\/|amazon\.com\/clog\/|youtube\.com\/ptracking|videowood\.tv\/pop2|static\.game\-state\.com\/images\/main\/alert\/replacement\/|thrixxx\.com\/affiliates\/|doubleclick\.net\/pfadx\/mc\.channelnewsasia\.com[^\w.%-]|ncrypt\.in\/images\/a\/|hostgator\.com\/~affiliat\/cgi\-bin\/affiliates\/|doubleclick\.net\/pfadx\/intl\.sps\.com\/|bristolairport\.co\.uk\/~\/media\/images\/brs\/blocks\/internal\-promo\-block\-300x250\/|supplyframe\.com\/partner\/|google\-analytics\.com\/collect|femalefirst\.co\.uk\/widgets\/|banners\.friday\-ad\.co\.uk\/hpbanneruploads\/|phncdn\.com\/images\/banners\/|doubleclick\.net\/adx\/wn\.nat\.|allmyvideos\.net\/js\/ad_|doubleclick\.net\/pfadx\/blp\.video\/midroll|doubleclick\.net\/pfadx\/nbcu\.nhl\.|doubleclick\.net\/pfadx\/nbcu\.nhl\/|wishlistproducts\.com\/affiliatetools\/|youtube\-nocookie\.com\/gen_204|doubleclick\.net\/pfadx\/tmz\.video\.wb\.dart\/|upsellit\.com\/custom\/|addthis\.com\/at\/|amazonaws\.com\/bo\-assets\/production\/banner_attachments\/|softpedia\-static\.com\/images\/aff\/|akamai\.net\/chartbeat\.|ad\.atdmt\.com\/m\/|doubleclick\.net\/pfadx\/bzj\.bizjournals\/|doubleclick\.net\/pfadx\/ndm\.tcm\/|theolympian\.com\/static\/images\/weathersponsor\/|bluehost\-cdn\.com\/media\/partner\/images\/|doubleclick\.net\/pfadx\/gn\.movieweb\.com\/|pussycash\.com\/content\/banners\/|staticneo\.com\/neoassets\/iframes\/leaderboard_bottom\.|doubleclick\.net\/pfadx\/miniclip\.midvideo\/|doubleclick\.net\/pfadx\/miniclip\.prevideo\/|mrc\.org\/sites\/default\/files\/uploads\/images\/Collusion_Banner|any\.gs\/visitScript\/|techkeels\.com\/creatives\/|amazonaws\.com\/publishflow\/|express\.de\/analytics\/|betwaypartners\.com\/affiliate_media\/|amazonaws\.com\/ownlocal\-|embed\.docstoc\.com\/Flash\.asmx\/StoreReffer|doubleclick\.net\/pfadx\/www\.tv3\.co\.nz|allanalpass\.com\/track\/|doubleclick\.net\/pfadx\/nbcu\.nbc\/|ebaystatic\.com\/aw\/signin\/ebay\-signin\-toyota\-|doubleclick\.net\/activity|urlcash\.org\/banners\/|bigrock\.in\/affiliate\/|doubleclick\.net\/xbbe\/creative\/vast|static\.twincdn\.com\/special\/script\.packed|twitch\.tv\/track\/|cloudfront\.net\/performable\/|updatetube\.com\/iframes\/|doubleclick\.net\/pfadx\/tmg\.telegraph\.|doubleclick\.net\/pfadx\/ddm\.ksl\/|publicbroadcasting\.net\/analytics\/|mail\.ru\/count\/|theseblogs\.com\/visitScript\/|sitegiant\.my\/affiliate\/|cdn77\.org\/tags\/|metromedia\.co\.za\/bannersys\/banners\/|beacons\.vessel\-static\.com\/xff|obox\-design\.com\/affiliate\-banners\/|singlehop\.com\/affiliates\/|tlavideo\.com\/affiliates\/|h2porn\.com\/contents\/content_sources\/|static\.twincdn\.com\/special\/license\.packed|sulia\.com\/papi\/sulia_partner\.js\/|ibtimes\.com\/banner\/|doubleclick\.net\/pfadx\/ccr\.|browsershots\.org\/static\/images\/creative\/|doubleclick\.net\/pfadx\/ng\.videoplayer\/|adm\.fwmrm\.net\/p\/mtvn_live\/|chefkoch\.de\/counter|apkmaza\.net\/wp\-content\/uploads\/|110\.45\.173\.103\/ad\/|goldmoney\.com\/~\/media\/Images\/Banners\/|filedownloader\.net\/design\/|hulkload\.com\/b\/|storage\.to\/affiliate\/|doubleclick\.net\/pfadx\/sugar\.poptv\/|dnsstuff\.com\/dnsmedia\/images\/ft\.banner\.|terra\.com\.br\/metrics\/|doubleclick\.net\/pfadx\/muzuoffsite\/|groupon\.com\/tracking|share\-online\.biz\/affiliate\/|usps\.com\/survey\/|camwhores\.tv\/banners\/|imagecarry\.com\/down|pedestrian\.tv\/_crunk\/wp\-content\/files_flutter\/|brettterpstra\.com\/wp\-content\/uploads\/|dnevnik\.si\/tracker\/|thebull\.com\.au\/admin\/uploads\/banners\/|e\-tailwebstores\.com\/accounts\/default1\/banners\/|doubleclick\.net\/pfadx\/ctv\.spacecast\/|drift\.com\/track|doubleclick\.net\/pfadx\/CBS\.|olark\.com\/track\/|mail\.ru\/counter|freemoviestream\.xyz\/wp\-content\/uploads\/|doubleclick\.net\/pfadx\/nfl\.|bruteforcesocialmedia\.com\/affiliates\/|homoactive\.tv\/banner\/|amazon\.com\/gp\/yourstore\/recs\/|gaccmidwest\.org\/uploads\/tx_bannermanagement\/|thenude\.eu\/media\/mxg\/|expertreviews\.co\.uk\/widget\/|debtconsolidationcare\.com\/affiliate\/tracker\/|yyv\.co\/track\/|1movies\.to\/site\/videoroller|dealextreme\.com\/affiliate_upload\/|vidible\.tv\/placement\/vast\/|appinthestore\.com\/click\/|dota\-trade\.com\/img\/branding_|plugins\.longtailvideo\.com\/yourlytics|vivatube\.com\/upload\/banners\/|epictv\.com\/sites\/default\/files\/290x400_|suite101\.com\/tracking\/|doubleclick\.net\/pfadx\/csn\.|doubleclick\.net\/pfadx\/muzumain\/|creativecdn\.com\/pix\/|aerotime\.aero\/upload\/banner\/|videos\.com\/click|filez\.cutpaid\.com\/336v|nfl\.com\/assets\/images\/hp\-poweredby\-|knco\.com\/wp\-content\/uploads\/wpt\/|petri\.co\.il\/wp\-content\/uploads\/banner1000x75_|petri\.co\.il\/wp\-content\/uploads\/banner700x475_|slack\.com\/beacon\/|thesundaily\.my\/sites\/default\/files\/twinskyscrapers|itweb\.co\.za\/logos\/|sectools\.org\/shared\/images\/p\/|preisvergleich\.de\/setcookie\/|sacbee\.com\/static\/dealsaver\/|babyblog\.ru\/pixel|media\.domainking\.ng\/media\/|hottubeclips\.com\/stxt\/banners\/|couptopia\.com\/affiliate\/|media\.enimgs\.net\/brand\/files\/escalatenetwork\/|flixcart\.com\/affiliate\/|infibeam\.com\/affiliate\/|lawdepot\.com\/affiliate\/|seedsman\.com\/affiliate\/|ppc\-coach\.com\/jamaffiliates\/|zap2it\.com\/wp\-content\/themes\/overmind\/js\/zcode\-|wonderlabs\.com\/affiliate_pro\/banners\/|vator\.tv\/tracking\/|putpat\.tv\/tracking|yea\.xxx\/img\/creatives\/|thenude\.eu\/affiliates\/|celebstoner\.com\/assets\/components\/bdlistings\/uploads\/|videovalis\.tv\/tracking\/|multiupload\.nl\/popunder\/|desert\.ru\/tracking\/|morningstaronline\.co\.uk\/offsite\/progressive\-listings\/|cnzz\.com\/stat\.|yahooapis\.com\/get\/Valueclick\/CapAnywhere\.getAnnotationCallback|wwe\.com\/sites\/all\/modules\/wwe\/wwe_analytics\/|punterlink\.co\.uk\/images\/storage\/siteban|whozacunt\.com\/images\/banner_|accuradio\.com\/static\/track\/|pwpwpoker\.com\/images\/banners\/|newoxfordreview\.org\/banners\/ad\-|c21media\.net\/wp\-content\/plugins\/sam\-images\/|hqq\.watch\/js\/betterj\/|worddictionary\.co\.uk\/static\/\/inpage\-affinity\/|wikipedia\.org\/beacon\/|doubleclick\.net\/pfadx\/ssp\.kgtv\/|visa\.com\/logging\/logEvent|optimum\.net\/utilities\/doubleclicktargeting|ru4\.com\/click|sapeople\.com\/wp\-content\/uploads\/wp\-banners\/|media\.complex\.com\/videos\/prerolls\/|expekt\.com\/affiliates\/|swurve\.com\/affiliates\/|axandra\.com\/affiliates\/|doubleclick\.net\/N5479\/pfadx\/ctv\.|ironsquid\.tv\/data\/uploads\/sponsors\/|blissful\-sin\.com\/affiliates\/|singlemuslim\.com\/affiliates\/|mangaupdates\.com\/affiliates\/|kontextr\.eu\/content\/track|bruteforceseo\.com\/affiliates\/|nmap\.org\/shared\/images\/p\/|seclists\.org\/shared\/images\/p\/|graduateinjapan\.com\/affiliates\/|uploaded\.to\/img\/public\/|rbth\.ru\/widget\/|ians\.in\/iansad\/|getadblock\.com\/images\/adblock_banners\/|themis\-media\.com\/media\/global\/images\/cskins\/|dailymail\.co\.uk\/tracking\/|doubleclick\.net\/adx\/tsg\.|kommersant\.uk\/banner_stats|myanimelist\.cdn\-dena\.com\/images\/affiliates\/|dpbolvw\.net\/image\-|anrdoezrs\.net\/image\-|mightydeals\.com\/widget|mixpanel\.com\/track|adyou\.me\/bug\/adcash|tsite\.jp\/static\/analytics\/|inphonic\.com\/tracking\/|nspmotion\.com\/tracking\/|inhumanity\.com\/cdn\/affiliates\/|russian\-dreams\.net\/static\/js\/|sextvx\.com\/static\/images\/tpd\-|proxysolutions\.net\/affiliates\/|saabsunited\.com\/wp\-content\/uploads\/180x460_|saabsunited\.com\/wp\-content\/uploads\/werbung\-|zambiz\.co\.zm\/banners\/|conde\.io\/beacon|theatm\.info\/images\/|tehrantimes\.com\/banner\/|dx\.com\/affiliate\/|iradio\.ie\/assets\/img\/backgrounds\/|nation\.sc\/images\/banners\/|citeulike\.org\/static\/campaigns\/|casti\.tv\/adds\/|vpnarea\.com\/affiliate\/|ask\.com\/servlets\/ulog|borrowlenses\.com\/affiliate\/|distrowatch\.com\/images\/kokoku\/|thereadystore\.com\/affiliate\/|ukcast\.tv\/adds\/|salemwebnetwork\.com\/Stations\/images\/SiteWrapper\/|myiplayer\.eu\/ad|taboola\.com\/tb|avito\.ru\/stat\/|live\-porn\.tv\/adds\/|204\.140\.25\.247\/ads\/|popeoftheplayers\.eu\/ad|whistleout\.com\.au\/imagelibrary\/ads\/wo_skin_|gameblog\.fr\/images\/ablock\/|eventful\.com\/tools\/click\/url|smn\-news\.com\/images\/banners\/|eccie\.net\/buploads\/|porn2blog\.com\/wp\-content\/banners\/|doubleclick\.net\/pfadx\/bet\.com\/|theday\.com\/assets\/images\/sponsorlogos\/|cloudfront\.net\/analyticsengine\/|freeporn\.to\/wpbanner\/|sdamgia\.ru\/img\/blockadblock_|timesinternet\.in\/ad\/|doubleclick\.net\/pfadx\/storm\.no\/|abplive\.in\/analytics\/|jenningsforddirect\.co\.uk\/sitewide\/extras\/|skroutz\.gr\/analytics\/|trustedreviews\.com\/mobile\/widgets\/html\/promoted\-phones|customerlobby\.com\/ctrack\-|allmovieportal\.com\/dynbanner\.|doubleclick\.net\/json|recomendedsite\.com\/addon\/upixel\/|talkphotography\.co\.uk\/images\/externallogos\/banners\/|shinypics\.com\/blogbanner\/|go\.com\/stat\/|aftonbladet\.se\/blogportal\/view\/statistics|s24cloud\.net\/metrics\/|ad2links\.com\/js\/|cdn\.69games\.xxx\/common\/images\/friends\/|ovpn\.to\/ovpn\.to\/banner\/|ed\-protect\.org\/cdn\-cgi\/apps\/head\/|sweed\.to\/affiliates\/|geometria\.tv\/banners\/|euphonik\.dj\/img\/sponsors\-|ejpress\.org\/img\/banners\/|digitalsatellite\.tv\/banners\/|yandex\.ru\/cycounter|djmag\.co\.uk\/sites\/default\/files\/takeover\/|alooma\.io\/track\/|ziffstatic\.com\/jst\/zdvtools\.|worldradio\.ch\/site_media\/banners\/|brandcdn\.com\/pixel\/|b2w\.io\/event\/|peggo\.tv\/ad\/|lipsy\.co\.uk\/_assets\/images\/skin\/tracking\/|hqfooty\.tv\/ad|xscores\.com\/livescore\/banners\/|examiner\.com\/sites\/all\/modules\/custom\/ex_stats\/|channel4\.com\/assets\/programmes\/images\/originals\/|needle\.com\/pageload|avira\.com\/site\/datatracking|oasap\.com\/images\/affiliate\/|nijobfinder\.co\.uk\/affiliates\/|justporno\.tv\/ad\/|desperateseller\.co\.uk\/affiliates\/|americanfreepress\.net\/assets\/images\/Banner_|doubleclick\.net\/adx\/CBS\.|omsnative\.de\/tracking\/|swagmp3\.com\/cdn\-cgi\/pe\/|pixazza\.com\/track\/|sysomos\.com\/track\/|luminate\.com\/track\/|picbucks\.com\/track\/|agitos\.de\/content\/track|targetspot\.com\/track\/|turnsocial\.com\/track\/|webdesignerdepot\.com\/wp\-content\/plugins\/md\-popup\/|reuters\.com\/tracker\/|tvducky\.com\/imgs\/graboid\.|foxadd\.com\/addon\/upixel\/|carambo\.la\/analytics\/|djmag\.com\/sites\/default\/files\/takeover\/|ximagehost\.org\/myman\.|nigeriafootball\.com\/img\/affiliate_|tamilwire\.org\/images\/banners3\/|getreading\.co\.uk\/static\/img\/bg_takeover_|galleries\.bz\/track\/|ball2win\.com\/Affiliate\/|dailymail\.co\.uk\/i\/pix\/ebay\/|lumfile\.com\/lumimage\/ourbanner\/|vitalmtb\.com\/assets\/vital\.aba\-|bbcchannels\.com\/workspace\/uploads\/|ziffstatic\.com\/jst\/zdsticky\.|slide\.com\/tracker\/|watchuseek\.com\/media\/1900x220_|va\.tawk\.to\/log|metroweekly\.com\/tools\/blog_add_visitor\/|1page\.co\.za\/affiliate\/|totalcmd\.pl\/img\/nucom\.|totalcmd\.pl\/img\/olszak\.|auto\.ru\/cookiesync\/|s\.holm\.ru\/stat\/|sciencecareers\.org\/widget\/|guru99\.com\/images\/adblocker\/|doubleclick\.net\/adx\/wn\.loc\.|theleader\.info\/banner|piano\.io\/tracker\/|frenchradiolondon\.com\/data\/carousel\/|concealednation\.org\/sponsors\/|early\-birds\.fr\/tracker\/|youporn\.com\/watch_postroll\/|4pda\.ru\/stat\/|karelia\.info\/counter\/|shop\.sportsmole\.co\.uk\/pages\/deeplink\/|graboid\.com\/affiliates\/|pixel\.indieclicktv\.com\/annonymous\/|bits\.wikimedia\.org\/geoiplookup|bitbond\.com\/affiliate\-program\/|uploading\.com\/static\/banners\/|traq\.li\/tracker\/|amy\.gs\/track\/|dyo\.gs\/track\/|gaccny\.com\/uploads\/tx_bannermanagement\/|ahk\-usa\.com\/uploads\/tx_bannermanagement\/|gaccwest\.com\/uploads\/tx_bannermanagement\/|gaccsouth\.com\/uploads\/tx_bannermanagement\/|pcmall\.co\.za\/affiliates\/|urbanvelo\.org\/sidebarbanner\/|videogame\.it\/a\/logview\/|amazonaws\.com\/fstrk\.net\/|yotv\.co\/adds\/|anti\-scam\.org\/abanners\/|relink\.us\/images\/|daily\-mail\.co\.zm\/images\/banners\/|onescreen\.net\/os\/static\/pixels\/|joblet\.jp\/javascripts\/|lgoat\.com\/cdn\/amz_|208\.91\.157\.30\/viewtrack\/|chelsey\.co\.nz\/uploads\/Takeovers\/|gamefront\.com\/wp\-content\/plugins\/tracker\/|hentaihaven\.org\/wp\-content\/banners\/|net\-parade\.it\/tracker\/|ab\-in\-den\-urlaub\.de\/usertracking\/|safarinow\.com\/affiliate\-zone\/|dailyhome\.com\/leaderboard_banner|annistonstar\.com\/leaderboard_banner|dailymotion\.com\/logger\/|tvbrowser\.org\/logo_df_tvsponsor_|clickandgo\.com\/booking\-form\-widget|hentaistream\.com\/wp\-includes\/images\/bg\-|m6web\.fr\/statsd\/|movie2kto\.ws\/popup|static\.multiplayuk\.com\/images\/w\/w\-|whitepages\.ae\/images\/UI\/SRA\/|whitepages\.ae\/images\/UI\/SRB\/|whitepages\.ae\/images\/UI\/WS\/|wiwo\.de\/analytics\/|tshirthell\.com\/img\/affiliate_section\/|itworld\.com\/slideshow\/iframe\/topimu\/|go2cdn\.org\/brand\/|fr\-online\.de\/analytics\/|tagesspiegel\.de\/analytics\/|thelodownny\.com\/leslog\/ads\/|berliner\-zeitung\.de\/analytics\/|medizinauskunft\.de\/logger\/|bluenile\.ca\/track\/|moneywise\.co\.uk\/affiliate\/|ehow\.com\/services\/jslogging\/log\/|mcvuk\.com\/static\/banners\/|armenpress\.am\/static\/add\/|fapdick\.com\/uploads\/fap_|chaturbate\.com\/sitestats\/openwindow\/|fapdick\.com\/uploads\/1fap_|vipbox\.tv\/js\/layer\-|attitude\.co\.uk\/images\/Music_Ticket_Button_|fuse\.tv\/images\/sponsor\/|agates\.ru\/counters\/|facebook\.com\/plugins\/|porntube\.com[^\w.%-](?=([\s\S]*?\/track))\1|facebook\.com[^\w.%-](?=([\s\S]*?\/tracking\.js))\2|bitgravity\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\3|youporn\.com[^\w.%-](?=([\s\S]*?\/tracker\.js))\4|clickfunnels\.com[^\w.%-](?=([\s\S]*?\/track))\5|cloudfront\.net(?=([\s\S]*?\/tracker\.js))\6|ninemsn\.com\.au[^\w.%-](?=([\s\S]*?\.tracking\.udc\.))\7|9msn\.com\.au[^\w.%-](?=([\s\S]*?\/tracking\/))\8|buzzfeed\.com[^\w.%-](?=([\s\S]*?\/tracker\.js))\9|gowatchit\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\10|svcs\.ebay\.com\/services\/search\/FindingService\/(?=([\s\S]*?[^\w.%-]affiliate\.tracking))\11|skype\.com[^\w.%-](?=([\s\S]*?\/track_channel\.js))\12|reevoo\.com[^\w.%-](?=([\s\S]*?\/track\/))\13|livefyre\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\14|goadv\.com[^\w.%-](?=([\s\S]*?\/track\.js))\15|forbes\.com[^\w.%-](?=([\s\S]*?\/track\.php))\16|msn\.com[^\w.%-](?=([\s\S]*?\/track\.js))\17|dealer\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\18|zdf\.de[^\w.%-](?=([\s\S]*?\/tracking))\19|dealer\.com[^\w.%-](?=([\s\S]*?\/tracker\/))\20|marketingpilgrim\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/trackur\.com\-))\21|staticwhich\.co\.uk\/assets\/(?=([\s\S]*?\/track\.js))\22|euroleague\.tv[^\w.%-](?=([\s\S]*?\/tracking\.js))\23|azurewebsites\.net[^\w.%-](?=([\s\S]*?\/mnr\-mediametrie\-tracking\-))\24|lemde\.fr[^\w.%-](?=([\s\S]*?\/tracking\/))\25|partypoker\.com[^\w.%-](?=([\s\S]*?\/tracking\-))\26|vectorstock\.com[^\w.%-](?=([\s\S]*?\/tracking))\27|fyre\.co[^\w.%-](?=([\s\S]*?\/tracking\/))\28|gazzettaobjects\.it[^\w.%-](?=([\s\S]*?\/tracking\/))\29|volkswagen\-italia\.it[^\w.%-](?=([\s\S]*?\/tracking\/))\30|comparis\.ch[^\w.%-](?=([\s\S]*?\/Tracking\/))\31|akamai\.net[^\w.%-](?=([\s\S]*?\/sitetracking\/))\32|trackitdown\.net\/skins\/(?=([\s\S]*?_campaign\/))\33|neulion\.vo\.llnwd\.net[^\w.%-](?=([\s\S]*?\/track\.js))\34|typepad\.com[^\w.%-](?=([\s\S]*?\/stats))\35|kat2\.biz\/(?=([\s\S]*?))\36|kickass2\.biz\/(?=([\s\S]*?))\37|doubleclick\.net[^\w.%-](?=([\s\S]*?\/ad\/))\38|adf\.ly\/(?=([\s\S]*?\.php))\39|doubleclick\.net[^\w.%-](?=([\s\S]*?\/adj\/))\40|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/adawe\-))\41|images\-amazon\.com[^\w.%-](?=([\s\S]*?\/Analytics\-))\42|r18\.com[^\w.%-](?=([\s\S]*?\/banner\/))\43|hulkshare\.com[^\w.%-](?=([\s\S]*?\/adsmanager\.js))\44|allmyvideos\.net\/(?=([\s\S]*?%))\45|allmyvideos\.net\/(?=([\s\S]*?))\46|images\-amazon\.com\/images\/(?=([\s\S]*?\/banner\/))\47|torrentproject\.ch\/(?=([\s\S]*?))\48|rackcdn\.com[^\w.%-](?=([\s\S]*?\/analytics\.js))\49|openload\.co[^\w.%-](?=([\s\S]*?\/_))\50|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/adaptvjw5\-))\51|freebunker\.com[^\w.%-](?=([\s\S]*?\/pops\.js))\52|213\.174\.140\.76[^\w.%-](?=([\s\S]*?\/js\/msn\.js))\53|amazonaws\.com[^\w.%-](?=([\s\S]*?\/pageviews))\54|thevideo\.me\/(?=([\s\S]*?\.php))\55|taboola\.com[^\w.%-](?=([\s\S]*?\/log\/))\56|xhcdn\.com[^\w.%-](?=([\s\S]*?\/ads_))\57|liutilities\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\58|urlcash\.net\/random(?=([\s\S]*?\.php))\59|oload\.tv[^\w.%-](?=([\s\S]*?\/_))\60|quantserve\.com[^\w.%-](?=([\s\S]*?\.swf))\61|blogsmithmedia\.com[^\w.%-](?=([\s\S]*?\/amazon_))\62|ifilm\.com\/website\/(?=([\s\S]*?_skin_))\63|freebunker\.com[^\w.%-](?=([\s\S]*?\/oc\.js))\64|kitguru\.net\/wp\-content\/uploads\/(?=([\s\S]*?\-Skin\.))\65|yimg\.com[^\w.%-](?=([\s\S]*?\/sponsored\.js))\66|imgflare\.com[^\w.%-](?=([\s\S]*?\/splash\.php))\67|bestofmedia\.com[^\w.%-](?=([\s\S]*?\/beacons\/))\68|thecatholicuniverse\.com[^\w.%-](?=([\s\S]*?\-ad\.))\69|skypeassets\.com[^\w.%-](?=([\s\S]*?\/inclient\/))\70|i3investor\.com[^\w.%-](?=([\s\S]*?\/partner\/))\71|paypal\.com[^\w.%-](?=([\s\S]*?\/pixel\.gif))\72|static\.(?=([\s\S]*?\.criteo\.net\/js\/duplo[^\w.%-]))\73|videogamesblogger\.com[^\w.%-](?=([\s\S]*?\/scripts\/takeover\.js))\74|thevideo\.me\/(?=([\s\S]*?_))\75|redtubefiles\.com[^\w.%-](?=([\s\S]*?\/banner\/))\76|meetlocals\.com[^\w.%-](?=([\s\S]*?popunder))\77|cloudzer\.net[^\w.%-](?=([\s\S]*?\/banner\/))\78|tumblr\.com[^\w.%-](?=([\s\S]*?\/sponsored_))\79|tumblr\.com[^\w.%-](?=([\s\S]*?_sponsored_))\80|xhcdn\.com[^\w.%-](?=([\s\S]*?\/sponsor\-))\81|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/ltas\-))\82|media\-imdb\.com[^\w.%-](?=([\s\S]*?\/affiliates\/))\83|avg\.com[^\w.%-](?=([\s\S]*?\/stats\.js))\84|widgetserver\.com[^\w.%-](?=([\s\S]*?\/image\.gif))\85|aolcdn\.com[^\w.%-](?=([\s\S]*?\/beacon\.min\.js))\86|facebook\.com\/ajax\/(?=([\s\S]*?\/log\.php))\87|speedcafe\.com[^\w.%-](?=([\s\S]*?\-banner\-))\88|static\.(?=([\s\S]*?\.criteo\.net\/images[^\w.%-]))\89|redtube\.com[^\w.%-](?=([\s\S]*?\/banner\/))\90|googleapis\.com[^\w.%-](?=([\s\S]*?\/gen_204))\91|eweek\.com[^\w.%-](?=([\s\S]*?\/sponsored\-))\92|images\-amazon\.com\/images\/(?=([\s\S]*?\/ga\.js))\93|google\.com[^\w.%-](?=([\s\S]*?\/log))\94|imagefruit\.com[^\w.%-](?=([\s\S]*?\/pops\.js))\95|idg\.com\.au\/images\/(?=([\s\S]*?_promo))\96|freebunker\.com[^\w.%-](?=([\s\S]*?\/raw\.js))\97|24hourwristbands\.com\/(?=([\s\S]*?\.googleadservices\.com\/))\98|yimg\.com[^\w.%-](?=([\s\S]*?\/flash\/promotions\/))\99|arstechnica\.net[^\w.%-](?=([\s\S]*?\/sponsor\-))\100|adswizz\.com\/adswizz\/js\/SynchroClient(?=([\s\S]*?\.js))\101|armorgames\.com[^\w.%-](?=([\s\S]*?\/banners\/))\102|yimg\.com[^\w.%-](?=([\s\S]*?\/ywa\.js))\103|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/FME\-Red\-CAP\.jpg))\104|postaffiliatepro\.com[^\w.%-](?=([\s\S]*?\/banners\/))\105|googlesyndication\.com[^\w.%-](?=([\s\S]*?\/googlevideoadslibraryas3\.swf))\106|thecatholicuniverse\.com[^\w.%-](?=([\s\S]*?\-advert\-))\107|turner\.com[^\w.%-](?=([\s\S]*?\/ads\/))\108|widgetserver\.com[^\w.%-](?=([\s\S]*?\/quantcast\.swf))\109|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/banner\.gif))\110|ibtimes\.com[^\w.%-](?=([\s\S]*?\/sponsor_))\111|gfi\.com\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\-BlogBanner))\112|lfcimages\.com[^\w.%-](?=([\s\S]*?\/partner\-))\113|virginmedia\.com[^\w.%-](?=([\s\S]*?\/analytics\/))\114|johngaltfla\.com\/wordpress\/wp\-content\/uploads\/(?=([\s\S]*?\/TB2K_LOGO\.jpg))\115|johngaltfla\.com\/wordpress\/wp\-content\/uploads\/(?=([\s\S]*?\/jmcs_specaialbanner\.jpg))\116|doubleclick\.net\/adx\/(?=([\s\S]*?\.NPR\.MUSIC\/))\117|pimpandhost\.com\/static\/i\/(?=([\s\S]*?\-pah\.jpg))\118|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/ibs\.orl\.news\/))\119|adamvstheman\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/AVTM_banner\.jpg))\120|financialsamurai\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/sliced\-alternative\-10000\.jpg))\121|phpbb\.com[^\w.%-](?=([\s\S]*?\/images\/hosting\/hostmonster\-downloads\.gif))\122|newstatesman\.com\/sites\/all\/themes\/(?=([\s\S]*?_1280x2000\.))\123|facebook\.com(?=([\s\S]*?\/impression\.php))\124|amazonaws\.com[^\w.%-](?=([\s\S]*?\/Test_oPS_Script_Loads))\125|yimg\.com[^\w.%-](?=([\s\S]*?\/fairfax\/))\126|imgbox\.com\/(?=([\s\S]*?\.html))\127|nichepursuits\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/long\-tail\-pro\-banner\.gif))\128|cdmagurus\.com\/img\/(?=([\s\S]*?\.gif))\129|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/PW\-Ad\.jpg))\130|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/DeadwoodStove\-PW\.gif))\131|opencurrency\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-aocs\-sidebar\-commodity\-bank\.png))\132|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/jihad\.jpg))\133|copblock\.org\/wp\-content\/uploads\/(?=([\s\S]*?\/covert\-handcuff\-key\-AD\-))\134|berush\.com\/images\/(?=([\s\S]*?_semrush_))\135|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/team\.car\/))\136|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/team\.dal\/))\137|queermenow\.net\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\-Banner))\138|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/embed\.ytpwatch\.))\139|flixster\.com[^\w.%-](?=([\s\S]*?\/analytics\.))\140|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/app\.ytpwatch\.))\141|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.MTV\-Viacom\/))\142|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.NBCUNI\.COM\/))\143|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/ccr\.newyork\.))\144|thehealthcareblog\.com\/files\/(?=([\s\S]*?\/American\-Resident\-Project\-Logo\-))\145|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.NBCUNIVERSAL\-CNBC\/))\146|thecommonsenseshow\.com\/siteupload\/(?=([\s\S]*?\/adsqmetals\.jpg))\147|walshfreedom\.com[^\w.%-](?=([\s\S]*?\/liberty\-luxury\.png))\148|mrc\.org[^\w.%-](?=([\s\S]*?\/Collusion_Banner300x250\.jpg))\149|nufc\.com[^\w.%-](?=([\s\S]*?\/The%20Gate_NUFC\.com%20banner_%2016\.8\.13\.gif))\150|linkbird\.com\/static\/upload\/(?=([\s\S]*?\/banner\/))\151|purpleporno\.com\/pop(?=([\s\S]*?\.js))\152|uflash\.tv[^\w.%-](?=([\s\S]*?\/affiliates\/))\153|allhiphop\.com\/site_resources\/ui\-images\/(?=([\s\S]*?\-conduit\-banner\.gif))\154|cooksunited\.co\.uk\/counter(?=([\s\S]*?\.php))\155|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Johnson\-Grow\-Lights\.gif))\156|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Judge\-Lenny\-001\.jpg))\157|mydramalist\.info[^\w.%-](?=([\s\S]*?\/affiliates\/))\158|netbiscuits\.net[^\w.%-](?=([\s\S]*?\/analytics\/))\159|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/apmgoldmembership250x250\.jpg))\160|marijuanapolitics\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/icbc1\.png))\161|marijuanapolitics\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/icbc2\.png))\162|thechive\.files\.wordpress\.com[^\w.%-](?=([\s\S]*?\-wallpaper\-))\163|reddit\.com[^\w.%-](?=([\s\S]*?_sponsor\.png))\164|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?_250x150\.png))\165|bitcoinreviewer\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/banner\-luckybit\.jpg))\166|zoover\.(?=([\s\S]*?\/shared\/bannerpages\/darttagsbanner\.aspx))\167|drivereasy\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/sidebar\-DriverEasy\-buy\.jpg))\168|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/com\.ytpwatch\.))\169|db\.com[^\w.%-](?=([\s\S]*?\/stats\.js))\170|queermenow\.net\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\/banner))\171|rghost\.ru\/download\/a\/(?=([\s\S]*?\/banner_download_))\172|telegraphindia\.com[^\w.%-](?=([\s\S]*?\/banners\/))\173|adz\.lk[^\w.%-](?=([\s\S]*?_ad\.))\174|cloudfront\.net(?=([\s\S]*?\/trk\.js))\175|ragezone\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/HV\-banner\-300\-200\.jpg))\176|tipico\.(?=([\s\S]*?\/affiliate\/))\177|techinsider\.net\/wp\-content\/uploads\/(?=([\s\S]*?\-300x500\.))\178|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.NBCUNIVERSAL\/))\179|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/team\.sd\/))\180|searchenginejournal\.com[^\w.%-](?=([\s\S]*?\/sponsored\-))\181|player\.screenwavemedia\.com[^\w.%-](?=([\s\S]*?\/ova\-jw\.swf))\182|saf\.org\/wp\-content\/uploads\/(?=([\s\S]*?\/theGunMagbanner\.png))\183|youku\.com[^\w.%-](?=([\s\S]*?\/click\.php))\184|ebaystatic\.com\/aw\/pics\/signin\/(?=([\s\S]*?_signInSkin_))\185|iimg\.in[^\w.%-](?=([\s\S]*?\/sponsor_))\186|thecommonsenseshow\.com\/siteupload\/(?=([\s\S]*?\/nightvisionadnew\.jpg))\187|preppersmallbiz\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/PSB\-Support\.jpg))\188|video\.abc\.com[^\w.%-](?=([\s\S]*?\/promos\/))\189|totallylayouts\.com[^\w.%-](?=([\s\S]*?\/users\-online\-counter\/online\.js))\190|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?_Side_Banner\.))\191|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?_Side_Banner_))\192|grouponcdn\.com[^\w.%-](?=([\s\S]*?\/affiliate_widget\/))\193|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.ABC\.com\/))\194|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/tsepulveda\-1\.jpg))\195|activewin\.com[^\w.%-](?=([\s\S]*?\/blaze_static2\.gif))\196|static\.ow\.ly[^\w.%-](?=([\s\S]*?\/click\.gz\.js))\197|thehealthcareblog\.com\/files\/(?=([\s\S]*?\/THCB\-Validic\-jpg\-opt\.jpg))\198|saf\.org\/wp\-content\/uploads\/(?=([\s\S]*?\/women_guns192x50\.png))\199|upcat\.custvox\.org\/survey\/(?=([\s\S]*?\/countOpen\.gif))\200|nfl\.com[^\w.%-](?=([\s\S]*?\/page\-background\-image\.jpg))\201|content\.ad\/Scripts\/widget(?=([\s\S]*?\.aspx))\202|freebunker\.com[^\w.%-](?=([\s\S]*?\/layer\.js))\203|s\-assets\.tp\-cdn\.com\/widgets\/(?=([\s\S]*?\/vwid\/))\204(?=([\s\S]*?\.html))\205|yimg\.com\/cv\/(?=([\s\S]*?\/billboard\/))\206|bestvpn\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/mosttrustedname_260x300_))\207|avito\.ru[^\w.%-](?=([\s\S]*?\/some\-pretty\-script\.js))\208|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/sensi2\.jpg))\209|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/cannafo\.jpg))\210|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/WeedSeedShop\.jpg))\211|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/gorillabanner728\.gif))\212|data\.ninemsn\.com\.au\/(?=([\s\S]*?GetAdCalls))\213|cannabisjobs\.us\/wp\-content\/uploads\/(?=([\s\S]*?\/OCWeedReview\.jpg))\214|doubleclick\.net\/(?=([\s\S]*?\/pfadx\/lin\.))\215|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.ESPN\/))\216|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.muzu\/))\217|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.BLIPTV\/))\218|doubleclick\.net\/pfadx\/(?=([\s\S]*?\/kidstv\/))\219|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/muzumain\/))\220|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.MCNONLINE\/))\221|doubleclick\.net\/pfadx\/(?=([\s\S]*?CBSINTERACTIVE\/))\222|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.VIACOMINTERNATIONAL\/))\223|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.WALTDISNEYINTERNETGROU\/))\224|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/dakine420\.png))\225|sify\.com[^\w.%-](?=([\s\S]*?\/gads_))\226|maciverse\.mangoco\.netdna\-cdn\.com[^\w.%-](?=([\s\S]*?banner))\227|thepreparednessreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?_175x175\.jpg))\228|thepreparednessreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?_185x185\.jpg))\229|malaysiabay\.org[^\w.%-](?=([\s\S]*?creatives\.php))\230|lfgcomic\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/PageSkin_))\231|heyjackass\.com\/wp\-content\/uploads\/(?=([\s\S]*?_300x225_))\232|nextbigwhat\.com\/wp\-content\/uploads\/(?=([\s\S]*?ccavenue))\233|wp\.com\/adnetsreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?banner))\234|googlesyndication\.com[^\w.%-](?=([\s\S]*?\/domainpark\.cgi))\235|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-250x250\.jpg))\236|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?_250x250\.jpg))\237|upload\.ee\/image\/(?=([\s\S]*?\/B_descarga_tipo12\.gif))\238|capitolfax\.com\/wp\-content\/(?=([\s\S]*?ad\.))\239|cardsharing\.info\/wp\-content\/uploads\/(?=([\s\S]*?\/ALLS\.jpg))\240|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?_300x400_))\241|starofmysore\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\-karbonn\.))\242|images\-pw\.secureserver\.net[^\w.%-](?=([\s\S]*?_))\243(?=([\s\S]*?\.))\244|sourcefed\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/netflix4\.jpg))\245|originalweedrecipes\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-Medium\.jpg))\246|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/free_ross\.jpg))\247|ebaystatic\.com\/aw\/signin\/(?=([\s\S]*?_wallpaper_))\248|dailyanimation\.studio[^\w.%-](?=([\s\S]*?\/banners\.))\249|saabsunited\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\-))\250|saabsunited\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\.))\251|saabsunited\.com\/wp\-content\/uploads\/(?=([\s\S]*?_banner_))\252|capitolfax\.com\/wp\-content\/(?=([\s\S]*?Ad_))\253|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/scrogger\.gif))\254|raysindex\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/dolmansept2012flash\.swf))\255|pastime\.biz[^\w.%-](?=([\s\S]*?\/personalad))\256(?=([\s\S]*?\.jpg))\257|survivaltop50\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Survival215x150Link\.png))\258|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/dynamic_banner_))\259|russiasexygirls\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/727x90))\260|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/ssp\.wews\/))\261|russiasexygirls\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/cb_))\262|libero\.it[^\w.%-](?=([\s\S]*?\/counter\.php))\263|i\.lsimg\.net[^\w.%-](?=([\s\S]*?\/sides_clickable\.))\264|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/180_350\.))\265|thejointblog\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-235x))\266|uniblue\.com[^\w.%-](?=([\s\S]*?\/affiliates\/))\267|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/xbt\-social\.png))\268|thepreparednessreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/250x125\-))\269|mofomedia\.nl\/pop\-(?=([\s\S]*?\.js))\270|morefree\.net\/wp\-content\/uploads\/(?=([\s\S]*?\/mauritanie\.gif))\271|mypbrand\.com\/wp\-content\/uploads\/(?=([\s\S]*?banner))\272|sfstatic\.com[^\w.%-](?=([\s\S]*?\/js\/fl\.js))\273|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/allserviceslogo\.gif))\274|thedailyblog\.co\.nz[^\w.%-](?=([\s\S]*?_Advert_))\275|thecompassionchronicles\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\-))\276|thecompassionchronicles\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\.))\277|gmstatic\.net[^\w.%-](?=([\s\S]*?\/amazonbadge\.png))\278|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/xbt\.jpg))\279|afcdn\.com[^\w.%-](?=([\s\S]*?\/ova\-jw\.swf))\280|islamicity\.org[^\w.%-](?=([\s\S]*?\/sponsorship\-))\281|947\.co\.za[^\w.%-](?=([\s\S]*?\-branding\.))\282|complexmedianetwork\.com[^\w.%-](?=([\s\S]*?\/toolbarlogo\.png))\283|seedr\.ru[^\w.%-](?=([\s\S]*?\/stats\/))\284|newsonjapan\.com[^\w.%-](?=([\s\S]*?\/banner\/))\285|freedom\.com[^\w.%-](?=([\s\S]*?\/analytics\/))\286|lego\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\287|talktalk\.co\.uk[^\w.%-](?=([\s\S]*?\/log\.html))\288|srwww1\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\289|allmovie\.com[^\w.%-](?=([\s\S]*?\/affiliate_))\290|tigerdirect\.com[^\w.%-](?=([\s\S]*?\/affiliate_))\291|zombiegamer\.co\.za\/wp\-content\/uploads\/(?=([\s\S]*?\-skin\-))\292|xrad\.io[^\w.%-](?=([\s\S]*?\/hotspots\/))\293|bizrate\.com[^\w.%-](?=([\s\S]*?\/survey_))\294|sillusions\.ws[^\w.%-](?=([\s\S]*?\/vpn\-banner\.gif))\295|doubleclick\.net\/adx\/(?=([\s\S]*?\.NPR\/))\296|hollyscoop\.com\/sites\/(?=([\s\S]*?\/skins\/))\297|nature\.com[^\w.%-](?=([\s\S]*?\/marker\-file\.nocache))\298|dada\.net[^\w.%-](?=([\s\S]*?\/nedstat_sitestat\.js))\299|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/cloudbet_))\300|lawprofessorblogs\.com\/responsive\-template\/(?=([\s\S]*?advert\.))\301|digitaltveurope\.net\/wp\-content\/uploads\/(?=([\s\S]*?_wallpaper_))\302|dailyherald\.com[^\w.%-](?=([\s\S]*?\/contextual\.js))\303|gaystarnews\.com[^\w.%-](?=([\s\S]*?\-sponsor\.))\304|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?\/sbt\.gif))\305|videoly\.co[^\w.%-](?=([\s\S]*?\/event\/))\306|ebaystatic\.com[^\w.%-](?=([\s\S]*?\/motorswidgetsv2\.swf))\307|atlantafalcons\.com\/wp\-content\/(?=([\s\S]*?\/metrics\.js))\308|eteknix\.com\/wp\-content\/uploads\/(?=([\s\S]*?Takeover))\309|foxandhoundsdaily\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-AD\.gif))\310|themittani\.com\/sites\/(?=([\s\S]*?\-skin))\311|wired\.com\/images\/xrail\/(?=([\s\S]*?\/samsung_layar_))\312|dell\.com\/images\/global\/js\/s_metrics(?=([\s\S]*?\.js))\313|dailyblogtips\.com\/wp\-content\/uploads\/(?=([\s\S]*?\.gif))\314|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-180x350\.))\315|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/180x350\.))\316|rapidfiledownload\.com[^\w.%-](?=([\s\S]*?\/btn\-input\-download\.png))\317|mmoculture\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-background\-))\318|spotify\.com[^\w.%-](?=([\s\S]*?\/metric))\319|signup\.advance\.net[^\w.%-](?=([\s\S]*?affiliate))\320|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/billpayhelp2\.png))\321|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/728_))\322|justsomething\.co\/wp\-content\/uploads\/(?=([\s\S]*?\-250x250\.))\323|vertical\-n\.de\/scripts\/(?=([\s\S]*?\/immer_oben\.js))\324|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.sevenload\.com_))\325|verticalnetwork\.de\/scripts\/(?=([\s\S]*?\/immer_oben\.js))\326|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/cmn_complextv\/))\327|allposters\.com[^\w.%-](?=([\s\S]*?\/banners\/))\328|guns\.ru[^\w.%-](?=([\s\S]*?\/banners\/))\329|samoatimes\.co\.nz[^\w.%-](?=([\s\S]*?\/banner468x60\/))\330|totallylayouts\.com[^\w.%-](?=([\s\S]*?\/visitor\-counter\/counter\.js))\331|nzpages\.co\.nz[^\w.%-](?=([\s\S]*?\/banners\/))\332|armorgames\.com[^\w.%-](?=([\s\S]*?\/siteskin\.css))\333|bassmaster\.com[^\w.%-](?=([\s\S]*?\/premier_sponsor_logo\/))\334|yimg\.com\/cv\/(?=([\s\S]*?\/config\-object\-html5billboardfloatexp\.js))\335|jdownloader\.org[^\w.%-](?=([\s\S]*?\/smbanner\.png))\336|tv3\.ie[^\w.%-](?=([\s\S]*?\/sponsor\.))\337|llnwd\.net\/o28\/assets\/(?=([\s\S]*?\-sponsored\-))\338|amazon\.(?=([\s\S]*?\/gp\/r\.html))\339|amazon\.(?=([\s\S]*?\/ajax\/counter))\340|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/ccn\.png))\341|between\-legs\.com[^\w.%-](?=([\s\S]*?\/banners\/))\342|galatta\.com[^\w.%-](?=([\s\S]*?\/banners\/))\343|hwscdn\.com[^\w.%-](?=([\s\S]*?\/brands_analytics\.js))\344|kvcr\.org[^\w.%-](?=([\s\S]*?\/sponsors\/))\345|star883\.org[^\w.%-](?=([\s\S]*?\/sponsors\.))\346|freecycle\.org[^\w.%-](?=([\s\S]*?\/sponsors\/))\347|nbr\.co\.nz[^\w.%-](?=([\s\S]*?\-WingBanner_))\348|agendize\.com[^\w.%-](?=([\s\S]*?\/counts\.jsp))\349|dreamscene\.org[^\w.%-](?=([\s\S]*?_Banner\.))\350|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?_270x312\.))\351|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?_1170x120\.))\352|serials\.ws[^\w.%-](?=([\s\S]*?\/logo\.gif))\353|ebaystatic\.com[^\w.%-](?=([\s\S]*?\/ScandalJS\-))\354|ebaystatic\.com[^\w.%-](?=([\s\S]*?\/ScandalSupportGFA\-))\355|adprimemedia\.com[^\w.%-](?=([\s\S]*?\/video_report\/videoReport\.php))\356|adprimemedia\.com[^\w.%-](?=([\s\S]*?\/video_report\/attemptAdReport\.php))\357|xxxgames\.biz[^\w.%-](?=([\s\S]*?\/sponsors\/))\358|thessdreview\.com[^\w.%-](?=([\s\S]*?\/owc\-full\-banner\.jpg))\359|aolcdn\.com\/os\/music\/img\/(?=([\s\S]*?\-skin\.jpg))\360|thessdreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/930x64_))\361|pbs\.org[^\w.%-](?=([\s\S]*?\/sponsors\/))\362|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/helix\.gif))\363|kexp\.org[^\w.%-](?=([\s\S]*?\/sponsoredby\.))\364|tremormedia\.com[^\w.%-](?=([\s\S]*?\/tpacudeoplugin46\.swf))\365|dnsstuff\.com\/dnsmedia\/images\/(?=([\s\S]*?_banner\.jpg))\366|edgecastcdn\.net[^\w.%-](?=([\s\S]*?\.barstoolsports\.com\/wp\-content\/banners\/))\367|pornsharing\.com\/App_Themes\/pornsharianew\/js\/adppornsharia(?=([\s\S]*?\.js))\368|pornsharing\.com\/App_Themes\/pornsharingnew\/js\/adppornsharia(?=([\s\S]*?\.js))\369|upickem\.net[^\w.%-](?=([\s\S]*?\/affiliates\/))\370)/i;
var bad_da_hostpath_regex_flag = 930 > 0 ? true : false;  // test for non-zero number of rules
    
// 174 rules as an efficient NFA RegExp:
var bad_da_RegExp = /^(?:[\w-]+\.)*?(?:porntube\.com\/ads$|ads\.|adv\.|1337x\.to[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|banner\.|banners\.|torrentz2\.eu[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|affiliate\.|affiliates\.|cloudfront\.net\/\?a=|erotikdeal\.com\/\?ref=|quantserve\.com\/pixel;|synad\.|cursecdn\.com\/shared\-assets\/current\/anchor\.js\?id=|yahoo\.com\/p\.gif;|bluehost\.com\/web\-hosting\/domaincheckapi\/\?affiliate=|kickass2\.st[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|oddschecker\.com\/clickout\.htm\?type=takeover\-|cloudfront\.net\/\?tid=|bittorrent\.am[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|sweed\.to\/\?pid=|qualtrics\.com\/WRSiteInterceptEngine\/\?Q_Impress=|katcr\.co[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|nowwatchtvlive\.ws[^\w.%-]\$csp=script\-src 'self' |tube911\.com\/scj\/cgi\/out\.php\?scheme_id=|x1337x\.ws[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|torrentdownloads\.me[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|uploadproper\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|movies\.askjolene\.com\/c64\?clickid=|ipornia\.com\/scj\/cgi\/out\.php\?scheme_id=|watchsomuch\.info[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|torrentfunk2\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|pirateiro\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|magnetdl\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|consensu\.org\/\?log=|torrentdownload\.ch[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|yourbittorrent2\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|limetorrents\.info[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|totalporn\.com\/videos\/tracking\/\?url=|api\.ticketnetwork\.com\/Events\/TopSelling\/domain=nytimes\.com|affiliates2\.|t\-online\.de[^\w.%-](?=([\s\S]*?\/stats\.js\?track=))\1|tinypic\.com\/api\.php\?(?=([\s\S]*?&action=track))\2|fantasti\.cc[^\w.%-](?=([\s\S]*?\?ad=))\3|casino\-x\.com[^\w.%-](?=([\s\S]*?\?partner=))\4|allmyvideos\.net\/(?=([\s\S]*?=))\5|quantserve\.com[^\w.%-](?=([\s\S]*?[^\w.%-]a=))\6|exashare\.com[^\w.%-](?=([\s\S]*?&h=))\7|blacklistednews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\8|ad\.atdmt\.com\/i\/(?=([\s\S]*?=))\9|swatchseries\.to[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\10|acidcow\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\11|thevideo\.me\/(?=([\s\S]*?\:))\12|1movies\.is[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' 'unsafe\-eval' data\: (?=([\s\S]*?\.jwpcdn\.com ))\13(?=([\s\S]*?\.gstatic\.com ))\14(?=([\s\S]*?\.googletagmanager\.com ))\15(?=([\s\S]*?\.addthis\.com ))\16(?=([\s\S]*?\.google\.com))\17|uptobox\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline' ))\18(?=([\s\S]*?\.gstatic\.com ))\19(?=([\s\S]*?\.google\.com ))\20(?=([\s\S]*?\.googleapis\.com))\21|phonearena\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\22|iyfsearch\.com[^\w.%-](?=([\s\S]*?&pid=))\23|2hot4fb\.com\/img\/(?=([\s\S]*?\.gif\?r=))\24|watchcartoononline\.io[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\25|merriam\-webster\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\26|flirt4free\.com[^\w.%-](?=([\s\S]*?&utm_campaign))\27|plista\.com\/widgetdata\.php\?(?=([\s\S]*?%22pictureads%22%7D))\28|pornsharing\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' 'unsafe\-eval' data\: (?=([\s\S]*?\.google\.com ))\29(?=([\s\S]*?\.gstatic\.com ))\30(?=([\s\S]*?\.google\-analytics\.com))\31|media\.campartner\.com\/index\.php\?cpID=(?=([\s\S]*?&cpMID=))\32|shortcuts\.search\.yahoo\.com[^\w.%-](?=([\s\S]*?&callback=yahoo\.shortcuts\.utils\.setdittoadcontents&))\33|wikia\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline' 'unsafe\-eval' ))\34(?=([\s\S]*?\.jwpsrv\.com ))\35(?=([\s\S]*?\.jwplayer\.com))\36|doubleclick\.net\/adj\/(?=([\s\S]*?\.collegehumor\/sec=videos_originalcontent;))\37|get\.(?=([\s\S]*?\.website\/static\/get\-js\?stid=))\38|sobusygirls\.fr[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-eval'))\39|postimg\.cc\/image\/\$csp=script\-src 'self' (?=([\s\S]*? data\: blob\: 'unsafe\-eval'))\40|unblocked\.win[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\41|videogamesblogger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\42(?=([\s\S]*?\.gstatic\.com ))\43(?=([\s\S]*?\.google\.com ))\44(?=([\s\S]*?\.googleapis\.com ))\45(?=([\s\S]*?\.playwire\.com ))\46(?=([\s\S]*?\.facebook\.com ))\47(?=([\s\S]*?\.bootstrapcdn\.com ))\48(?=([\s\S]*?\.twitter\.com ))\49(?=([\s\S]*?\.spot\.im))\50|eafyfsuh\.net[^\w.%-](?=([\s\S]*?\/\?name=))\51|lijit\.com\/blog_wijits\?(?=([\s\S]*?=trakr&))\52|btkitty\.pet[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' (?=([\s\S]*?\.cloudflare\.com ))\53(?=([\s\S]*?\.googleapis\.com ))\54(?=([\s\S]*?\.jsdelivr\.net))\55|bighealthreport\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\56(?=([\s\S]*?\.gstatic\.com ))\57(?=([\s\S]*?\.google\.com ))\58(?=([\s\S]*?\.googleapis\.com ))\59(?=([\s\S]*?\.playwire\.com ))\60(?=([\s\S]*?\.facebook\.com ))\61(?=([\s\S]*?\.bootstrapcdn\.com ))\62(?=([\s\S]*?\.yimg\.com))\63|linkbucks\.com[^\w.%-](?=([\s\S]*?\/\?))\64(?=([\s\S]*?=))\65|pockettactics\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\66|answerology\.com\/index\.aspx\?(?=([\s\S]*?=ads\.ascx))\67|freehostedscripts\.net[^\w.%-](?=([\s\S]*?\.php\?site=))\68(?=([\s\S]*?&s=))\69(?=([\s\S]*?&h=))\70|ifly\.com\/trip\-plan\/ifly\-trip\?(?=([\s\S]*?&ad=))\71|facebook\.com\/(?=([\s\S]*?\/plugins\/send_to_messenger\.php\?app_id=))\72|torrentz\.eu\/search(?=([\s\S]*?=))\73|doubleclick\.net\/pfadx\/(?=([\s\S]*?adcat=))\74|solarmovie\.one[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\75|freebeacon\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\76|viralnova\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\77(?=([\s\S]*?\.gstatic\.com ))\78(?=([\s\S]*?\.google\.com ))\79(?=([\s\S]*?\.googleapis\.com ))\80(?=([\s\S]*?\.playwire\.com ))\81(?=([\s\S]*?\.facebook\.com ))\82(?=([\s\S]*?\.bootstrapcdn\.com))\83|tipico\.(?=([\s\S]*?\?affiliateId=))\84|extremetech\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\85|shopify\.com\/(?=([\s\S]*?\/page\?))\86(?=([\s\S]*?&eventType=))\87|waybig\.com\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\?pas=))\88|rover\.ebay\.com\.au[^\w.%-](?=([\s\S]*?&cguid=))\89|barbwire\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\90(?=([\s\S]*?\.gstatic\.com ))\91(?=([\s\S]*?\.google\.com ))\92(?=([\s\S]*?\.googleapis\.com ))\93(?=([\s\S]*?\.playwire\.com ))\94(?=([\s\S]*?\.facebook\.com ))\95(?=([\s\S]*?\.bootstrapcdn\.com))\96|thehayride\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\97(?=([\s\S]*?\.gstatic\.com ))\98(?=([\s\S]*?\.google\.com ))\99(?=([\s\S]*?\.googleapis\.com ))\100(?=([\s\S]*?\.playwire\.com ))\101(?=([\s\S]*?\.facebook\.com ))\102(?=([\s\S]*?\.bootstrapcdn\.com))\103|wakingtimes\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\104(?=([\s\S]*?\.gstatic\.com ))\105(?=([\s\S]*?\.google\.com ))\106(?=([\s\S]*?\.googleapis\.com ))\107(?=([\s\S]*?\.playwire\.com ))\108(?=([\s\S]*?\.facebook\.com ))\109(?=([\s\S]*?\.bootstrapcdn\.com))\110|activistpost\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\111(?=([\s\S]*?\.gstatic\.com ))\112(?=([\s\S]*?\.google\.com ))\113(?=([\s\S]*?\.googleapis\.com ))\114(?=([\s\S]*?\.playwire\.com ))\115(?=([\s\S]*?\.facebook\.com ))\116(?=([\s\S]*?\.bootstrapcdn\.com))\117|allthingsvegas\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\118(?=([\s\S]*?\.gstatic\.com ))\119(?=([\s\S]*?\.google\.com ))\120(?=([\s\S]*?\.googleapis\.com ))\121(?=([\s\S]*?\.playwire\.com ))\122(?=([\s\S]*?\.facebook\.com ))\123(?=([\s\S]*?\.bootstrapcdn\.com))\124|survivalnation\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\125(?=([\s\S]*?\.gstatic\.com ))\126(?=([\s\S]*?\.google\.com ))\127(?=([\s\S]*?\.googleapis\.com ))\128(?=([\s\S]*?\.playwire\.com ))\129(?=([\s\S]*?\.facebook\.com ))\130(?=([\s\S]*?\.bootstrapcdn\.com))\131|thelibertydaily\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\132(?=([\s\S]*?\.gstatic\.com ))\133(?=([\s\S]*?\.google\.com ))\134(?=([\s\S]*?\.googleapis\.com ))\135(?=([\s\S]*?\.playwire\.com ))\136(?=([\s\S]*?\.facebook\.com ))\137(?=([\s\S]*?\.bootstrapcdn\.com))\138|visiontoamerica\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\139(?=([\s\S]*?\.gstatic\.com ))\140(?=([\s\S]*?\.google\.com ))\141(?=([\s\S]*?\.googleapis\.com ))\142(?=([\s\S]*?\.playwire\.com ))\143(?=([\s\S]*?\.facebook\.com ))\144(?=([\s\S]*?\.bootstrapcdn\.com))\145|comicallyincorrect\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\146(?=([\s\S]*?\.gstatic\.com ))\147(?=([\s\S]*?\.google\.com ))\148(?=([\s\S]*?\.googleapis\.com ))\149(?=([\s\S]*?\.playwire\.com ))\150(?=([\s\S]*?\.facebook\.com ))\151(?=([\s\S]*?\.bootstrapcdn\.com))\152|americasfreedomfighters\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\153(?=([\s\S]*?\.gstatic\.com ))\154(?=([\s\S]*?\.google\.com ))\155(?=([\s\S]*?\.googleapis\.com ))\156(?=([\s\S]*?\.playwire\.com ))\157(?=([\s\S]*?\.facebook\.com ))\158(?=([\s\S]*?\.bootstrapcdn\.com))\159|bulletsfirst\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\160(?=([\s\S]*?\.gstatic\.com ))\161(?=([\s\S]*?\.google\.com ))\162(?=([\s\S]*?\.googleapis\.com ))\163(?=([\s\S]*?\.playwire\.com ))\164(?=([\s\S]*?\.facebook\.com ))\165(?=([\s\S]*?\.bootstrapcdn\.com))\166|skyscanner\.(?=([\s\S]*?\/slipstream\/applog$))\167|tipico\.com[^\w.%-](?=([\s\S]*?\?affiliateid=))\168|amazon\.com\/gp\/(?=([\s\S]*?&linkCode))\169|yifyddl\.movie[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' (?=([\s\S]*?\.googleapis\.com))\170|hop\.clickbank\.net\/(?=([\s\S]*?&transaction_id=))\171(?=([\s\S]*?&offer_id=))\172|computerarts\.co\.uk\/(?=([\s\S]*?\.php\?cmd=site\-stats))\173|123unblock\.xyz[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\174|unblocked\.pet[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\175|moviewatcher\.is[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\176|unblockall\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\177|onion\.ly[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\178|machinenoveltranslation\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\179|fullmatchesandshows\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\180|nintendoeverything\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\181|textsfromlastnight\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\182|powerofpositivity\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\183|talkwithstranger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\184|readliverpoolfc\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\185|androidcentral\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\186|roadracerunner\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\187|tetrisfriends\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\188|thisisfutbol\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\189|almasdarnews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\190|colourlovers\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\191|convertfiles\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\192|investopedia\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\193|skidrowcrack\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\194|sportspickle\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\195|hiphopearly\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\196|readarsenal\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\197|kshowonline\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\198|moneyversed\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\199|thehornnews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\200|torrentfunk\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\201|videocelts\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\202|britannica\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\203|csgolounge\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\204|grammarist\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\205|healthline\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\206|tworeddots\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\207|wuxiaworld\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\208|kiplinger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\209|readmng\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\210|trifind\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\211|vidmax\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\212|debka\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\213|biology\-online\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\214|menrec\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\215(?=([\s\S]*?\.google\.com ))\216(?=([\s\S]*?\.googleapis\.com ))\217(?=([\s\S]*?\.facebook\.com ))\218(?=([\s\S]*?\.bootstrapcdn\.com ))\219(?=([\s\S]*?\.twitter\.com ))\220(?=([\s\S]*?\.spot\.im))\221|ipatriot\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\222(?=([\s\S]*?\.google\.com ))\223(?=([\s\S]*?\.googleapis\.com ))\224(?=([\s\S]*?\.facebook\.com ))\225(?=([\s\S]*?\.bootstrapcdn\.com ))\226(?=([\s\S]*?\.twitter\.com ))\227(?=([\s\S]*?\.spot\.im))\228|clashdaily\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\229(?=([\s\S]*?\.google\.com ))\230(?=([\s\S]*?\.googleapis\.com ))\231(?=([\s\S]*?\.facebook\.com ))\232(?=([\s\S]*?\.bootstrapcdn\.com ))\233(?=([\s\S]*?\.twitter\.com ))\234(?=([\s\S]*?\.spot\.im))\235|dcdirtylaundry\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\236(?=([\s\S]*?\.google\.com ))\237(?=([\s\S]*?\.googleapis\.com ))\238(?=([\s\S]*?\.facebook\.com ))\239(?=([\s\S]*?\.bootstrapcdn\.com ))\240(?=([\s\S]*?\.twitter\.com ))\241(?=([\s\S]*?\.spot\.im))\242|thinkamericana\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\243(?=([\s\S]*?\.google\.com ))\244(?=([\s\S]*?\.googleapis\.com ))\245(?=([\s\S]*?\.facebook\.com ))\246(?=([\s\S]*?\.bootstrapcdn\.com ))\247(?=([\s\S]*?\.twitter\.com ))\248(?=([\s\S]*?\.spot\.im))\249|godfatherpolitics\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\250(?=([\s\S]*?\.google\.com ))\251(?=([\s\S]*?\.googleapis\.com ))\252(?=([\s\S]*?\.facebook\.com ))\253(?=([\s\S]*?\.bootstrapcdn\.com ))\254(?=([\s\S]*?\.twitter\.com ))\255(?=([\s\S]*?\.spot\.im))\256|libertyunyielding\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\257(?=([\s\S]*?\.google\.com ))\258(?=([\s\S]*?\.googleapis\.com ))\259(?=([\s\S]*?\.facebook\.com ))\260(?=([\s\S]*?\.bootstrapcdn\.com ))\261(?=([\s\S]*?\.twitter\.com ))\262(?=([\s\S]*?\.spot\.im))\263|conservativefiringline\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\264(?=([\s\S]*?\.google\.com ))\265(?=([\s\S]*?\.googleapis\.com ))\266(?=([\s\S]*?\.facebook\.com ))\267(?=([\s\S]*?\.bootstrapcdn\.com ))\268(?=([\s\S]*?\.twitter\.com ))\269(?=([\s\S]*?\.spot\.im))\270|ancient\-origins\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\271|asheepnomore\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\272|campussports\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\273|toptenz\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\274|online\.mydirtyhobby\.com[^\w.%-](?=([\s\S]*?\?naff=))\275|cts\.tradepub\.com\/cts4\/\?ptnr=(?=([\s\S]*?&tm=))\276|truthuncensored\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\277(?=([\s\S]*?\.google\.com ))\278(?=([\s\S]*?\.googleapis\.com ))\279(?=([\s\S]*?\.facebook\.com ))\280(?=([\s\S]*?\.bootstrapcdn\.com ))\281(?=([\s\S]*?\.twitter\.com ))\282(?=([\s\S]*?\.spot\.im))\283|blog\-rct\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\284|lolcounter\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\285|nsfwyoutube\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\286|thecelticblog\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\287|videolike\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\288|broadwayworld\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\289|miniurls\.co[^\w.%-](?=([\s\S]*?\?ref=))\290|prox4you\.pw[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\291|winit\.winchristmas\.co\.uk[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\292)/i;
var bad_da_regex_flag = 174 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_url_parts_RegExp = /^$/;
var good_url_parts_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 2601 rules as an efficient NFA RegExp:
var bad_url_parts_RegExp = /(?:\/adcontent\.|\/adsys\/|\/adserver\.|\/pp\-ad\.|\.com\/ads\?|\?getad=&|\/img\/adv\.|\/img\/adv\/|\/expandable_ad\?|\.online\/ads\/|\/online\/ads\/|\/online\-ad_|_online_ad\.|\/ad\-engine\.|\/ad_engine\?|\/homepage\-ads\/|\/homepage\/ads\/|\-online\-advert\.|\/imgad\.|\/imgad\?|\-web\-ad\-|\/web\-ad_|\/iframead\.|\/iframead\/|\/contentad\/|\/contentad$|\-leaderboard\-ad\-|\/leaderboard_ad\.|\/leaderboard_ad\/|\-ad\-content\/|\/ad\/content\/|\/ad_content\.|\/adcontent\/|\/ad\-images\/|\/ad\/images\/|\/ad_images\/|\/ad\-image\.|\/ad\/image\/|\/ad_image\.|\/static\/tracking\/|\/webad\?|_webad\.|\/adplugin\.|\/adplugin\/|\/adplugin_|\-content\-ad\-|\-content\-ad\.|\/content\/ad\/|\/content\/ad_|\/content_ad\.|_content_ad\.|\-iframe\-ad\.|\/iframe\-ad\.|\/iframe\-ad\/|\/iframe\-ad\?|\/iframe\.ad\/|\/iframe\/ad\/|\/iframe\/ad_|\/iframe_ad\.|\/iframe_ad\?|\/video\-ad\.|\/video\/ad\/|\/video_ad\.|\.com\/video\-ad\-|\-ad_leaderboard\/|\/ad\-leaderboard\.|\/ad\/leaderboard\.|\/ad_leaderboard\.|\/ad_leaderboard\/|=ad\-leaderboard\-|_js\/ads\.js|\/superads_|\/web\-analytics\.|\/web_analytics\/|\/_img\/ad_|\/img\/_ad\.|\/img\/ad\-|\/img\/ad\.|\/img\/ad\/|\/img_ad\/|\/assets\/js\/ad\.|=adcenter&|\.adriver\.|\/adriver\.|\/adriver_|\.com\/\?adv=|\/popad$|\/t\/event\.js\?|\/pop2\.js$|\-ad\-iframe\.|\-ad\-iframe\/|\-ad\/iframe\/|\/ad\-iframe\-|\/ad\-iframe\.|\/ad\-iframe\?|\/ad\/iframe\.|\/ad\/iframe\/|\/ad\?iframe_|\/ad_iframe\.|\/ad_iframe_|=ad_iframe&|=ad_iframe_|\/xtclicks\.|\/xtclicks_|\/bottom\-ads\.|\/ad\.php$|\-text\-ads\.|\/post\/ads\/|_search\/ads\.js|\/expandable_ad\.php|\/bg\/ads\/|\-top\-ads\.|\/top\-ads\.|\-show\-ads\.|\/show\-ads\.|\.net\/ad\/|\/footer\-ads\/|\/ad132m\/|\/inc\/ads\/|\/adclick\.|\.co\/ads\/|\-iframe\-ads\/|\/iframe\-ads\/|\/iframe\/ads\/|\-ads\-iframe\.|\/ads\/iframe|\/ads_iframe\.|\/mobile\-ads\/|\/afs\/ads\/|\/special\-ads\/|\/ad\?count=|\/ad_count\.|\/ad_pop\.php\?|\-article\-ads\-|\-video\-ads\/|\/video\-ads\/|\/video\.ads\.|\/video\/ads\/|\/dynamic\/ads\/|\/modules\/ads\/|\.no\/ads\/|\/user\/ads\?|\/mini\-ads\/|\/ad\/logo\/|\/js\/ads\-|\/js\/ads\.|\/js\/ads_|\/pc\/ads\.|\/i\/ads\/|\/vast\/ads\-|\/showads\/|\/cms\/ads\/|\/player\/ads\.|\/player\/ads\/|\/ads\.cms|\/remove\-ads\.|\/ads\/html\/|\/td\-ads\-|_track\/ad\/|\/external\/ads\/|\/ext\/ads\/|\/left\-ads\.|\/default\/ads\/|\/responsive\-ads\.|\/media\/ad\/|\/house\-ads\/|\/ad\?sponsor=|\/ads\/click\?|\/delivery\.ads\.|\/ads12\.|\/custom\/ads|\-adskin\.|\/adskin\/|\/adsetup\.|\/adsetup_|\/adsframe\.|\/sidebar\-ads\/|\/ads\/targeting\.|\/ads_reporting\/|\/blogad\.|\/adsdaq_|\/popupads\.|\/click\?adv=|\/adbanners\/|\/ads\/async\/|\/image\/ads\/|\/image\/ads_|&program=revshare&|\/ads\.htm|\/click\.track\?|\/banner\-adv\-|\/banner\/adv\/|\/banner\/adv_|\.ads\.css|\/ads\.css|\/adlog\.|\/realmedia\/ads\/|\/analytics\.gif\?|\/adsrv\.|\/adsrv\/|\-peel\-ads\-|\/adsys\.|\/log\/ad\-|\/log_ad\?|\/aff_ad\?|\/sponsored_ad\.|\/sponsored_ad\/|\/plugins\/ads\-|\/plugins\/ads\/|\/partner\.ads\.|\/ads\.php|\/ads_php\/|\/ads8\.|\/ads8\/|\/adsjs\.|\/adsjs\/|\/ad_video\.htm|\.link\/ads\/|\/adstop\.|\/adstop_|\/lazy\-ads\-|\/lazy\-ads\.|\.ads1\-|\.ads1\.|\/ads1\.|\/ads1\/|\/video\-ad\-overlay\.|&adcount=|\-adbanner\.|\.adbanner\.|\/adbanner\.|\/adbanner\/|\/adbanner_|=adbanner_|\/adpartner\.|\?adpartner=|\/ads\/square\-|\/ads\/square\.|\/new\-ads\/|\/new\/ads\/|\/ads\.js\.|\/ads\.js\/|\/ads\.js\?|\/ads\/js\.|\/ads\/js\/|\/ads\/js_|\/adClick\/|\/adClick\?|\/s_ad\.aspx\?|\/google_tag\.|\/google_tag\/|\/blog\/ads\/|\-adsonar\.|\/adsonar\.|\/flash\-ads\.|\/flash\-ads\/|\/flash\/ads\/|\/ads\/text\/|\/ads_text_|=popunders&|\.ads9\.|\/ads9\.|\/ads9\/|\.adserve\.|\/adserve\-|\/adserve\.|\/adserve\/|\/adserve_|\/home\/ads\-|\/home\/ads\/|\/home\/ads_|\-adsystem\-|\/adsystem\.|\/adsystem\/|\/bannerad\.|\/bannerad\/|_bannerad\.|&popunder=|\/popunder\.|\/popunder_|=popunder&|_popunder\+|&adspace=|\-adspace\.|\-adspace_|\.adspace\.|\/adspace\.|\/adspace\/|\/adspace\?|\/ad\.html\?|\/ad\/html\/|\/ad_html\/|\/ads\-new\.|\/ads_new\.|\/ads_new\/|\.ads3\-|\/ads3\.|\/ads3\/|\-banner\-ads\-|\-banner\-ads\/|\/banner\-ads\-|\/banner\-ads\/|\/ad\/js\/pushdown\.|\/ads\-top\.|\/ads\/top\-|\/ads\/top\.|\/ads_top_|\.adsense\.|\/adsense\-|\/adsense\/|\/adsense\?|;adsense_|\/a\-ads\.|\/bin\/stats\?|\/ads\/index\-|\/ads\/index\.|\/ads\/index\/|\/ads\/index_|\/web\-ads\.|\/web\-ads\/|\/web\/ads\/|=web&ads=|\-img\/ads\/|\/img\-ads\.|\/img\-ads\/|\/img\.ads\.|\/img\/ads\/|\/adstat\.|\/site\-ads\/|\/site\/ads\/|\/site\/ads\?|\.ads2\-|\/ads2\.|\/ads2\/|\/ads2_|\-dfp\-ads\/|\/dfp\-ads\.|\/dfp\-ads\/|\-adscript\.|\/adscript\.|\/adscript\?|\/adscript_|\.com\/counter\?|_mobile\/js\/ad\.|\/admanager\/|\/images\.ads\.|\/images\/ads\-|\/images\/ads\.|\/images\/ads\/|\/images\/ads_|_images\/ads\/|\-search\-ads\.|\/search\-ads\?|\/search\/ads\?|\/search\/ads_|\/adb_script\/|\/google\/adv\.|\/adshow\-|\/adshow\.|\/adshow\/|\/adshow\?|\/adshow_|=adshow&|&adserver=|\-adserver\-|\-adserver\.|\-adserver\/|\.adserver\.|\/adserver\-|\/adserver\/|\/adserver\?|\/adserver_|\/assets\/sponsored\/|\/media\/ads\/|_media\/ads\/|\/ajax\/track\.php\?|\/plugins\/ad\.|\-ad\-banner\-|\-ad\-banner\.|\-ad_banner\-|\/ad\-banner\-|\/ad\-banner\.|\/ad\/banner\.|\/ad\/banner\/|\/ad\/banner\?|\/ad\/banner_|\/ad_banner\.|\/ad_banner\/|\/ad_banner_|\/static\/ads\/|_static\/ads\/|\-banner\-ad\-|\-banner\-ad\.|\-banner\-ad\/|\/banner\-ad\-|\/banner\-ad\.|\/banner\-ad\/|\/banner\-ad_|\/banner\/ad\.|\/banner\/ad\/|\/banner\/ad_|\/banner_ad\.|_banner\-ad\.|_banner_ad\-|_banner_ad\.|_banner_ad\/|\-google\-ads\-|\-google\-ads\/|\/google\-ads\.|\/google\-ads\/|\/product\-ad\/|\/pages\/ads|\/videoad\.|_videoad\.|\/tracker\/tracker\.js|\.com\/js\/ads\/|\/googlead\-|\/googlead\.|_googlead\.|\/adpreview\?|\/js\/_analytics\/|\/js\/analytics\.|\/advlink\.|\?AdUrl=|\-images\/ad\-|\/images\-ad\/|\/images\/ad\-|\/images\/ad\/|\/images_ad\/|_images\/ad\.|_images\/ad_|\.com\/stats\.ashx\?|\/ads\/popshow\.|\/my\-ad\-injector\/|\.com\/ads\-|\.com\/ads\.|\.com\/ads_|\/com\/ads\/|\/ad\-minister\-|\.net\/adx\.php\?|&advertiserid=|\/video\-ads\-management\.|\/adworks\/|=advertiser\.|=advertiser\/|\?advertiser=|\/userad\/|\/adblocker\/pixel\.|\/ga_social_tracking_|_mainad\.|\/admax\/|_WebAd[^\w.%-]|\/goad$|\-ad0\.|\/video\-ads\-player\.|_ad\.png\?|\/embed\-log\.js|\/public\/js\/ad\/|\/adwords\/|\/ad\-manager\/|\/ad_manager\.|\/ad_manager\/|\.com\/im\-ad\/|\.com\/im_ad\/|\/adimg\/|\/adfactory\-|\/adfactory_|\/adplayer\-|\/adplayer\/|\.com\/\?ad=|\.com\/ad\?|\/js\/oas\-|\/js\/oas\.|\-adops\.|\/adops\/|=adlabs&|\/ajax\-track\-view\.|\/adseo\/|\-google\-ad\.|\/google\-ad\-|\/google\-ad\?|\/google\/ad\?|\/google_ad\.|_google_ad\.|\/adlink\?|\/adlink_|\/adsterra\/|\/images\/adver\-|\/ad\.css\?|\-advertising\/assets\/|\/tracking\/track\.php\?|\/analytics\-v1\.|\/ads\/ads\.|\/ads\/ads\/|\/ads\/ads_|\/\?addyn$|\-advt\.|\/advt\/|\-ad\-pixel\-|\/\?advideo\/|\?advideo_|\/admedia\/|_smartads_|\/socialads\/|\/tracker\/track\.php\?|\/track\/track\.php\?|\.ads4\-|\/ads4\/|\/utep_ad\.js|\/images\/ad2\/|\-adman\/|\/adman\/|\/adman_|\/wp\-content\/ads\/|\/flashads\/|\/_\/ads\/|\-adtrack\.|\/adtrack\/|\/campaign\/advertiser_|\/adbroker\.|\/adbroker\/|\/adnow\-|\/pop_ad\.|_pop_ad\.|_pop_ad\/|\/sensorsdata\-|\/g_track\.php\?|\/amp\-ad\-|\.net\/ads\-|\.net\/ads\.|\.net\/ads\/|\.net\/ads\?|\.net\/ads_|\/advertisments\/|\-image\-ad\.|\/image\/ad\/|\?adx=|\/chartbeat\.js|_chartbeat\.js|&adurl=|\/adblock\-img\.|\/img\-advert\-|\/admaster\?|\/adservice\-|\/adservice\/|\/adservice$|\/ero\-advertising\.|\/adblock_alerter\.|\/adblock\-alerter\/|\/show\-ad\.|\/show\.ad\?|\/show_ad\.|\/show_ad\?|\?affiliate=|\/ajax\/optimizely\-|\/intelliad\.|\.core\.tracking\-min\-|&adnet=|\/adx\/iframe\.|\/adx_iframe_|\/adv\-expand\/|\/leaderboard\-advert\.|\/pixel\/js\/|\/adiframe\.|\/adiframe\/|\/adiframe\?|\/adiframe_|\/getad\/|\/getad\?|\/exoclick$|\-adspot\-|\/adspot\/|\/adspot_|\?adspot_|\/analytics\/track\-|\/analytics\/track\.|\/analytics\/track\/|\/analytics\/track\?|\/analytics\/track$|\/adrolays\.|_doubleclick\.|\/googleads\-|\/googleads\/|\/googleads_|_googleads_|\/nuggad\.|\/nuggad\/|\/adcash\-|\/adcash$|\/ad_pop\.|\/adguru\.|\.net\/ad2\/|\/adhandler\.|\/adfox\/|\?adfox_|\/adimages\.|\/iframes\/ad\/|\/google\-analytics\-|\/google\-analytics\.|\/google\/analytics_|\/google_analytics\.|\/cpx\-advert\/|\/adverthorisontalfullwidth\.|\/adblockDetector\.|\.AdmPixelsCacheController\?|\/adaptvexchangevastvideo\.|\/ForumViewTopicContentAD\.|\/postprofilehorizontalad\.|=adreplacementWrapperReg\.|\/adwizard\.|\/adwizard\/|\/adwizard_|\/adClosefeedbackUpgrade\.|\/adzonecenteradhomepage\.|\/ForumViewTopicBottomAD\.|\/adverserve\.|\/advertisementrotation\.|\/advertisingimageexte\/|\/AdvertisingIsPresent6\?|\/postprofileverticalad\.|\/adblockdetectorwithga\.|\/admanagementadvanced\.|\/advertisementmapping\.|\/initlayeredwelcomead\-|\/advertisementheader\.|\/advertisingcontent\/|\/advertisingwidgets\/|\/thirdpartyframedad\/|\.AdvertismentBottom\.|\/adfrequencycapping\.|\/adgearsegmentation\.|\/advertisementview\/|\/advertising300x250\.|\/advertverticallong\.|\/AdZonePlayerRight2\.|\/ShowInterstitialAd\.|\/addeliverymodule\/|\/adinsertionplugin\.|\/AdPostInjectAsync\.|\/adrendererfactory\.|\/advertguruonline1\.|\/advertisementAPI\/|\/advertisingbutton\.|\/advertisingmanual\.|\/advertisingmodule\.|\/adzonebelowplayer\.|\/adzoneplayerright\.|\/jumpstartunpaidad\.|\?adtechplacementid=|\/adasiatagmanager\.|\/adforgame160x600\.|\/adframe728homebh\.|\/adleaderboardtop\.|\/adpositionsizein\-|\/adreplace160x600\.|\/advertise125x125\.|\/advertisement160\.|\/advertiserwidget\.|\/advertisinglinks_|\/advFrameCollapse\.|\/requestmyspacead\.|\/supernorthroomad\.|\/adblockdetection\.|\/adBlockDetector\/|\.advertrecycling\.|\/adbriteincleft2\.|\/adbriteincright\.|\/adchoicesfooter\.|\/adgalleryheader\.|\/adindicatortext\.|\/admatcherclient\.|\/adoverlayplugin\.|\/adreplace728x90\.|\/adtaggingsubsec\.|\/adtagtranslator\.|\/adultadworldpop_|\/advertisements2\.|\/advertisewithus_|\/adWiseShopPlus1\.|\/adwrapperiframe\.|\/contentmobilead\.|\/convertjsontoad\.|\/HompageStickyAd\.|\/mobilephonesad\/|\/sample300x250ad\.|\/tomorrowfocusAd\.|\/adforgame728x90\.|\/adforgame728x90_|\-web\-advert\-|_web\-advert\.|\/AdblockMessage\.|\/AdAppSettings\/|\/adinteraction\/|\/adaptvadplayer\.|\/adcalloverride\.|\/adfeedtestview\.|\/adframe120x240\.|\/adframewrapper\.|\/adiframeanchor\.|\/adlantisloader\.|\/adlargefooter2\.|\/adpanelcontent\.|\/adverfisement2\.|\/advertisement1\.|\/advertisement2\.|\/advertisement3\.|\/dynamicvideoad\?|\/premierebtnad\/|\/rotatingtextad\.|\/sample728x90ad\.|\/slideshowintad\?|\/adblockchecker\.|\/adblockdetect\.|\/adblockdetect\/|\-advertising11\.|\/adchoicesicon\.|\/adframe728bot\.|\/adframebottom\.|\/adframecommon\.|\/adframemiddle\.|\/adinsertjuicy\.|\/adlargefooter\.|\/adleftsidebar\.|\/admanagement\/|\/adMarketplace\.|\/admentorserve\.|\/adotubeplugin\.|\/adPlaceholder\.|\/advaluewriter\.|\/adverfisement\.|\/advertbuttons_|\/advertising02\.|\/advertisment1\-|\/advertisment4\.|\/bottomsidead\/|\/getdigitalad\/|\/gigyatargetad\.|\/gutterspacead\.|\/leaderboardad\.|\/newrightcolad\.|\/promobuttonad\.|\/rawtubelivead\.|\/restorationad\-|=admodeliframe&|\/adblockkiller\.|\/addpageview\/|\/admonitoring\.|&customSizeAd=|\-printhousead\-|\.advertmarket\.|\/AdBackground\.|\/adcampaigns\/|\/adcomponent\/|\/adcontroller\.|\/adfootcenter\.|\/adframe728b2\.|\/adifyoverlay\.|\/admeldscript\.|\/admentor302\/|\/admentorasp\/|\/adnetwork300\.|\/adnetwork468\.|\/AdNewsclip14\.|\/AdNewsclip15\.|\/adoptionicon\.|\/adrequisitor\-|\/adTagRequest\.|\/adtechHeader\.|\/adtechscript\.|\/adTemplates\/|\/advertisings\.|\/advertsquare\.|\/advertwebapp\.|\/advolatility\.|\/adzonebottom\.|\/adzonelegend\.|\/brightcovead\.|\/contextualad\.|\/custom11x5ad\.|\/horizontalAd\.|\/iframedartad\.|\/indexwaterad\.|\/jsVideoPopAd\.|\/PageBottomAD\.|\/skyscraperad\.|\/writelayerad\.|=dynamicwebad&|\-advertising2\-|\/advertising2\.|\/get\-advert\-|\/advtemplate\/|\/advtemplate_|\/adimppixel\/|\-adcompanion\.|\-adtechfront\.|\-advertise01\.|\-rightrailad\-|\.xinhuanetAD\.|\/728x80topad\.|\/adchoices16\.|\/adchoicesv4\.|\/adcollector\.|\/adcontainer\?|\/addelivery\/|\/adfeedback\/|\/adfootright\.|\/AdformVideo_|\/adfoxLoader_|\/adframe728a\.|\/adframe728b\.|\/adfunctions\.|\/adgenerator\.|\/adgraphics\/|\/adhandlers2\.|\/adheadertxt\.|\/adhomepage2\.|\/adiframetop\.|\/admanagers\/|\/admetamatch\?|\/adpictures\/|\/adpolestar\/|\/adPositions\.|\/adproducts\/|\/adrequestvo\.|\/adrollpixel\.|\/adtopcenter\.|\/adtopmidsky\.|\/advcontents\.|\/advertises\/|\/advertlayer\.|\/advertright\.|\/advscripts\/|\/adzoneright\.|\/asyncadload\.|\/crossoverad\-|\/dynamiccsad\?|\/gexternalad\.|\/indexrealad\.|\/instreamad\/|\/internetad\/|\/lifeshowad\/|\/newtopmsgad\.|\/o2contentad\.|\/propellerad\.|\/showflashad\.|\/SpotlightAd\-|\/targetingAd\.|_companionad\.|\.adplacement=|\/adplacement\.|\/adversting\/|\/adversting\?|\-NewStockAd\-|\.adgearpubs\.|\.rolloverad\.|\/300by250ad\.|\/adbetween\/|\/adbotright\.|\/adboxtable\-|\/adbriteinc\.|\/adchoices2\.|\/adcontents_|\/AdElement\/|\/adexclude\/|\/adexternal\.|\/adfillers\/|\/adflashes\/|\/adFooterBG\.|\/adfootleft\.|\/adformats\/|\/adframe120\.|\/adframe468\.|\/adframetop\.|\/adhandlers\-|\/adhomepage\.|\/adiframe18\.|\/adiframem1\.|\/adiframem2\.|\/adInfoInc\/|\/adlanding\/|\/admanager3\.|\/admanproxy\.|\/admcoreext\.|\/adorika300\.|\/adorika728\.|\/adperfdemo\.|\/AdPreview\/|\/adprovider\.|\/adreplace\/|\/adrequests\.|\/adrevenue\/|\/adrightcol\.|\/adrotator2\.|\/adtextmpu2\.|\/adtopright\.|\/adv180x150\.|\/advertical\.|\/advertmsig\.|\/advertphp\/|\/advertpro\/|\/advertrail\.|\/advertstub\.|\/adviframe\/|\/advlink300\.|\/advrotator\.|\/advtarget\/|\/AdvWindow\/|\/adwidgets\/|\/adWorking\/|\/adwrapper\/|\/adxrotate\/|\/AdZoneAdXp\.|\/adzoneleft\.|\/baselinead\.|\/deliverad\/|\/DynamicAd\/|\/getvideoad\.|\/lifelockad\.|\/lightboxad[^\w.%-]|\/neudesicad\.|\/onplayerad\.|\/photo728ad\.|\/postprocad\.|\/pushdownAd\.|\/PVButtonAd\.|\/renewalad\/|\/rotationad\.|\/sidelinead\.|\/slidetopad\.|\/tripplead\/|\?adlocation=|\?adunitname=|_preorderad\.|\-adrotation\.|\/adgallery2\.|\/adgallery2$|\/adgallery3\.|\/adgallery3$|\/adinjector\.|\/adinjector_|\/adpicture1\.|\/adpicture1$|\/adpicture2\.|\/adpicture2$|\/adrotation\.|\/externalad\.|_externalad\.|\-adfliction\.|\-adfliction\/|\/adfliction\-|\/adbDetect\.|\/adbDetect\/|\/adcontrol\.|\/adcontrol\/|\/adinclude\.|\/adinclude\/|\/adkingpro\-|\/adkingpro\/|\/adoverlay\.|\/adoverlay\/|\/widget\-advert\.|\/widget\-advert\?|&adgroupid=|&adpageurl=|\-Ad300x250\.|\-ContentAd\-|\/125x125ad\.|\/300x250ad\.|\/ad125x125\.|\/ad160x600\.|\/ad1x1home\.|\/ad2border\.|\/ad2gather\.|\/ad300home\.|\/ad300x145\.|\/ad600x250\.|\/ad600x330\.|\/ad728home\.|\/adactions\.|\/adasset4\/|\/adbayimg\/|\/adblock26\.|\/adbotleft\.|\/adcentral\.|\/adchannel_|\/adclutter\.|\/adengage0\.|\/adengage1\.|\/adengage2\.|\/adengage3\.|\/adengage4\.|\/adengage5\.|\/adengage6\.|\/adexample\?|\/adfetcher\?|\/adfolder\/|\/adforums\/|\/adheading_|\/adiframe1\.|\/adiframe2\.|\/adiframe7\.|\/adiframe9\.|\/adinator\/|\/AdLanding\.|\/adLink728\.|\/adlock300\.|\/admarket\/|\/admeasure\.|\/admentor\/|\/adNdsoft\/|\/adonly468\.|\/adopspush\-|\/adoptions\.|\/adreclaim\-|\/adrelated\.|\/adruptive\.|\/adtopleft\.|\/adunittop$|\/advengine\.|\/advertize_|\/advertsky\.|\/advertss\/|\/adverttop\.|\/advfiles\/|\/adviewas3\.|\/advloader\.|\/advscript\.|\/advzones\/|\/adwriter2\.|\/adyard300\.|\/adzonetop\.|\/AtomikAd\/|\/contentAd\.|\/contextad\.|\/delayedad\.|\/devicead\/|\/dynamicad\?|\/fetchJsAd\.|\/galleryad\.|\/getTextAD\.|\/GetVASTAd\?|\/invideoad\.|\/MonsterAd\-|\/PageTopAD\.|\/pitattoad\.|\/prerollad\.|\/processad\.|\/ProductAd\.|\/proxxorad\.|\/showJsAd\/|\/siframead\.|\/slideinad\.|\/sliderAd\/|\/spiderad\/|\/testingad\.|\/tmobilead\.|\/unibluead\.|\/vert728ad\.|\/vplayerad\.|\/VXLayerAd\-|\/welcomead\.|=DisplayAd&|\?adcentric=|\?adcontext=|\?adflashid=|\?adversion=|\?advsystem=|\/admonitor\-|\/admonitor\.|\/adrefresh\-|\/adrefresh\.|\/defaultad\.|\/defaultad\?|\/adconfig\.|\/adconfig\/|\/addefend\.|\/addefend\/|\/adfactor\/|\/adfactor_|\/adframes\.|\/adframes\/|\/adloader\.|\/adloader\/|\/adwidget\/|\/adwidget_|\/bottomad\.|\/bottomad\/|\/buttonad\/|_buttonad\.|&adclient=|\/adclient\-|\/adclient\.|\/adclient\/|\-Ad300x90\-|\-adcentre\.|\/768x90ad\.|\/ad120x60\.|\/ad1place\.|\/ad290x60_|\/ad468x60\.|\/ad468x80\.|\/AD728cat\.|\/ad728rod\.|\/adarena\/|\/adasset\/|\/adblockl\.|\/adblockr\.|\/adborder\.|\/adbot160\.|\/adbot300\.|\/adbot728\.|\/adbottom\.|\/AdBoxDiv\.|\/adboxes\/|\/adbrite2\.|\/adbucket\.|\/adbucks\/|\/adcast01_|\/adcframe\.|\/adcircle\.|\/adcodes\/|\/adcommon\?|\/adcxtnew_|\/addeals\/|\/adError\/|\/adfooter\.|\/adframe2\.|\/adfront\/|\/adgetter\.|\/adheader\.|\/adhints\/|\/adifyids\.|\/adindex\/|\/adinsert\.|\/aditems\/|\/adlantis\.|\/adleader\.|\/adlinks2\.|\/admicro2\.|\/adModule\.|\/adnotice\.|\/adonline\.|\/adpanel\/|\/adparts\/|\/adplace\/|\/adplace5_|\/adremote\.|\/adroller\.|\/adtagcms\.|\/adtaobao\.|\/adtimage\.|\/adtonomy\.|\/adtop160\.|\/adtop300\.|\/adtop728\.|\/adtopsky\.|\/adtvideo\.|\/advelvet\-|\/advert01\.|\/advert24\.|\/advert31\.|\/advert32\.|\/advert33\.|\/advert34\.|\/advert35\.|\/advert36\.|\/advert37\.|\/adverweb\.|\/adviewed\.|\/adviewer\.|\/adzilla\/|\/anchorad\.|\/attachad\.|\/bigboxad\.|\/btstryad\.|\/couponAd\.|\/customad\.|\/getmyad\/|\/gutterAd\.|\/incmpuad\.|\/injectad\.|\/insertAd\.|\/insideAD\.|\/jamnboad\.|\/jstextad\.|\/leaderad\.|\/localAd\/|\/masterad\.|\/mstextad\?|\/multiad\/|\/noticead\.|\/notifyad\.|\/pencilad\.|\/pledgead\.|\/proto2ad\.|\/salesad\/|\/scrollAd\-|\/spacead\/|\/squaread\.|\/stickyad\.|\/stocksad\.|\/topperad\.|\/tribalad\.|\/VideoAd\/|\/widgetad\.|=ad320x50\-|=adexpert&|\?adformat=|\?adPageCd=|\?adTagUrl=|_adaptvad\.|_StickyAd\.|\-adhelper\.|\/468x60ad\.|\/adhelper\.|\/admarker\.|\/admarker_|\/commonAD\.|\/footerad\.|\/footerad\?|\/headerad\.|_468x60ad\.|_commonAD\.|_headerad\.|\-admarvel\/|\.admarvel\.|\/admarvel\.|\/adometry\-|\/adometry\.|\/adometry\?|\/adition\.|\/adcycle\.|\/adcycle\/|\/adfiles\.|\/adfiles\/|\/adpeeps\.|\/adpeeps\/|\/adproxy\.|\/adproxy\/|\/advalue\/|\/advalue_|\/adzones\.|\/adzones\/|\/printad\.|\/printad\/|\/servead\.|\/servead\/|\-adimage\-|\/adimage\.|\/adimage\/|\/adimage\?|\.biz\/ad2\/|\/adpixel\.|&largead=|\-adblack\-|\-adhere2\.|\/ad160px\.|\/ad2gate\.|\/ad2push\.|\/ad300f2\.|\/ad300ws\.|\/ad728f2\.|\/ad728ws\.|\/AdAgent_|\/adanim\/|\/adasync\.|\/adboxbk\.|\/adbridg\.|\/adbytes\.|\/adcache\.|\/adctrl\/|\/adedge\/|\/adentry\.|\/adfeeds\.|\/adfever_|\/adflash\.|\/adfshow\?|\/adfuncs\.|\/adgear1\-|\/adgear2\-|\/adhtml\/|\/adlandr\.|\/ADMark\/|\/admatch\-|\/admatik\.|\/adnexus\-|\/adning\/|\/adpagem\.|\/adpatch\.|\/adplan4\.|\/adpoint\.|\/adpool\/|\/adpop32\.|\/adprove_|\/adpush\/|\/adratio\.|\/adroot\/|\/adrotat\.|\/adrotv2\.|\/adtable_|\/adtadd1\.|\/adtagtc\.|\/adtext2\.|\/adtext4\.|\/adtomo\/|\/adtraff\.|\/adutils\.|\/advault\.|\/advdoc\/|\/advert4\.|\/advert5\.|\/advert6\.|\/advert8\.|\/adverth\.|\/advinfo\.|\/adVisit\.|\/advris\/|\/advshow\.|\/adweb33\.|\/adwise\/|\/adzbotm\.|\/adzerk2_|\/adzone1\.|\/adzone4\.|\/bookad\/|\/coread\/|\/flashad\.|\/flytead\.|\/gamead\/|\/hoverad\.|\/imgaad\/|\/jsonad\/|\/LayerAd[^\w.%-]|\/modalad\.|\/nextad\/|\/panelad\.|\/photoad\.|\/promoAd\.|\/rpgetad\.|\/safead\/|\/ServeAd\?|\/smartAd\?|\/transad\.|\/trendad\.|\?adclass=|&advtile=|&smallad=|\-advert3\.|\-sync2ad\-|\.adforge\.|\.admicro\.|\/adcheck\.|\/adcheck\?|\/adfetch\.|\/adfetch\?|\/adforge\.|\/adlift4\.|\/adlift4_|\/adlinks\.|\/adlinks_|\/admicro_|\/adttext\-|\/adttext\.|\/advert3\.|\/smallad\-|\/sync2ad\.|\?advtile=|\-adchain\.|\-advert2\.|\/adchain\-|\/adchain\.|\/advert2\-|\/advert2\.|\/layerad\-|\/layerad\.|_layerad\.|\/admeta\.|=admeta&|\/adfile\.|\/adfile\/|\/adleft\.|\/adleft\/|\/peelad\.|\/peelad\/|\/sidead\.|\/sidead\/|\/viewad\.|\/viewad\/|\/viewad\?|_sidead\.|\/ad2\/index\.|&adzone=|\/adzone\.|\/adzone\/|\/adzone_|\?adzone=|\/adinfo\?|\/adpv2\/|\/adtctr\.|\/adtrk\/|&adname=|&AdType=|\.adnwif\.|\.adpIds=|\/ad000\/|\/ad125b\.|\/ad136\/|\/ad160k\.|\/ad2010\.|\/ad2con\.|\/ad300f\.|\/ad300s\.|\/ad300x\.|\/ad728f\.|\/ad728s\.|\/ad728t\.|\/ad728w\.|\/ad728x\.|\/adbar2_|\/adbase\.|\/adbebi_|\/adbl1\/|\/adbl2\/|\/adbl3\/|\/adblob\.|\/adbox1\.|\/adbox2\.|\/adcast_|\/adcla\/|\/adcomp\.|\/adcss\/|\/add728\.|\/adfeed\.|\/adfly\/|\/adicon_|\/adinit\.|\/adjoin\.|\/adjsmp\.|\/adjson\.|\/adkeys\.|\/adlens\-|\/admage\.|\/admega\.|\/adnap\/|\/ADNet\/|\/adnet2\.|\/adnew2\.|\/adpan\/|\/adperf_|\/adping\.|\/adpix\/|\/adplay\.|\/AdPub\/|\/adRoll\.|\/adtabs\.|\/adtago\.|\/adunix\.|\/adutil\.|\/Adv150\.|\/Adv468\.|\/advobj\.|\/advPop\.|\/advts\/|\/advweb\.|\/adweb2\.|\/adx160\.|\/adyard\.|\/adztop\.|\/ajaxAd\?|\/baseAd\.|\/bnrad\/|\/boomad\.|\/cashad\.|\/cubead\.|\/curlad\.|\/cutead\.|\/DemoAd\.|\/dfpad\/|\/divad\/|\/drawad\.|\/ebayad\.|\/flatad\.|\/freead\.|\/fullad\.|\/geoad\/|\/GujAd\/|\/idleAd\.|\/ipadad\.|\/livead\-|\/metaad\.|\/MPUAd\/|\/navad\/|\/newAd\/|\/Nuggad\?|\/postad\.|\/railad\.|\/retrad\.|\/rollad\.|\/rotad\/|\/svnad\/|\/tinyad\.|\/toonad\.|=adMenu&|\?adarea=|\?advurl=|&adflag=|&adlist=|\.adwolf\.|\/adback\.|\/adback\?|\/adflag\.|\/adlist_|\/admain\.|\/admain$|\/adwolf\.|\/adworx\.|\/adworx_|\/footad\-|\/footad\.|\/skinad\.|_skinad\.|\.lazyad\-|\/lazyad\-|\/lazyad\.|\/gujAd\.|\/adpic\.|\/adpic\/|\/adwiz\.|\/adwiz\/|\/flyad\.|\/flyad\/|\/adimp\?|\/adpv\/|&adnum=|\-NewAd\.|\-webAd\-|\/120ad\.|\/300ad\.|\/468ad\.|\/ad11c\.|\/ad125\.|\/ad160\.|\/ad234\.|\/ad250\.|\/ad336\.|\/ad350\.|\/ad468\.|\/adban\.|\/adbet\-|\/adbot_|\/adbtr\.|\/adbug_|\/adCfg\.|\/adcgi\?|\/adfrm\.|\/adGet\.|\/adGpt\.|\/adhug_|\/adixs\.|\/admgr\.|\/adnex\.|\/adpai\.|\/adPos\?|\/adrun\.|\/advdl\.|\/advf1\.|\/advhd\.|\/advph\.|\/advt2\.|\/adxcm_|\/adyea\.|\/affad\?|\/bizad\.|\/buyad\.|\/ciaad\.|\/cnxad\-|\/getAd;|\/ggad\/|\/KfAd\/|\/kitad\.|\/layad\.|\/ledad\.|\/mktad\.|\/mpuad\.|\/natad\.|\/picAd\.|\/pubad\.|\/subAd\.|\/txtad\.|\/ypad\/|\?adloc=|\?PopAd=|_125ad\.|_250ad\.|_FLYAD\.|\.homad\.|\.intad\.|\.intad\/|\/ad728\-|\/ad728\.|\/adrot\.|\/adrot_|\/newad\.|\/newad\?|_homad\.|\/adrum\-|\/adrum\.|\/adrum_|\/2\/ads\/|\-advertising\/vast\/|\/ajax\-advert\-|\/ajax\-advert\.|\/jsad\/|\/admp\-|\-ad03\.|\.adru\.|\/ad12\.|\/ad15\.|\/ad1r\.|\/ad3i\.|\/ad41_|\/ad4i\.|\/adbn\?|\/adfr\.|\/adjk\.|\/adnl\.|\/adv1\.|\/adv2\.|\/adv5\.|\/adv6\.|\/adv8\.|\/adw1\.|\/adw2\.|\/adw3\.|\/adx2\.|\/adxv\.|\/bbad\.|\/cyad\.|\/o2ad\.|\/pgad\.|\/1\/ads\/|\.win\/ads\/|\/ad_campaigns\/|\/ad8\.|\/telegraph\-advertising\/|\/bg\-advert\-|\/collections\/ads\-|\/Ad\.asmx\/|\.com\/log\?event|\/adx\-exchange\.|\/ad_contents\/|\/banner\.asp\?|\/wp_stat\.php\?|\-analytics\/analytics\.|\/adtest\.|\/adtest\/|\/ad2\/res\/|\.com\/ad2\/|\-js\-advertising\-|\.com\/js\/ad\.|\/adgallery1\.|\/adgallery1$|\/img2\/ad\/|\?ad\.vid=|\/stream\-ad\.|\/site_under\.|\/bottom\-advert\-|\.nl\/ad2\/|\/ad\/swf\/|\/content\/adv\/|\.uk\/track\?|\/ados\?|\/advs\/|\-advert\-placeholder\.|\/cn\-advert\.|\/clickability\-|\/clickability\/|\/clickability\?|_clickability\/|\-gif\-advert\.|\/scripts\/adv\.|\/ad\.aspx\?|\/adv_script_|\/script\-adv\-|\?advert_key=|\-article\-advert\-|\/article\-advert\-|_tracker_min\.|\/ad\/img\/|\/ad_img\.|\/ad_img\/|\/affiliate_link\.js|\/layer\-advert\-|\.v4\.analytics\.|\/v4\/analytics\.|\?adunitid=|\/images\.adv\/|\/images\/adv\-|\/images\/adv\.|\/images\/adv\/|\/images\/adv_|\/google\/analytics\.js|\/ad2\-728\-|\-advert\-100x100\.|\/site\-advert\.|\/native\-advertising\/|\/click\-stat\.js|\/e\-advertising\/|\/ad24\/|\/wp\-admin\/admin\-ajax\.php\?action=adblockvisitor|\/event\-tracking\.js|\/wp\-srv\/ad\/|\/wp\-content\/plugins\/wp\-super\-popup\-pro\/|\-ads\-manager\/|\/ads_manager\.|\/scripts\/ad\-|\/scripts\/ad\.|\/scripts\/ad\/|\/scripts\/ad_|\/stats\/tracker\.js|\-ad1\.|\/ad1_|\-ad\-scripts\?|\/show_ads\.js|\/adsatt\.|\/ad\/script\/|\/ad_script\.|\/ad_script_|\/statistics\.php\?data=|\?adunit_id=|\.php\?id=ads_|\.com\/adds\/|\/global\-analytics\.js|\/ga_link_tracker_|\/adpicture\.|\/eureka\-ads\.|\/ad\/afc_|\/scripts\/stats\/|\-page\-ad\.|\-page\-ad\?|\/page\/ad\/|\/adv3\.|\.jsp\?adcode=|\/adclix\.|\/analytics\.v1\.js|\/ads_9_|\/stat\-analytics\/|\/set\-cookie\.gif\?|\/static\/js\/4728ba74bc\.js|&advid=|\/adtype\.|\/adtype=|\?adtype=|\-ad\-left\.|\/ad\-left\.|\/ad_left\.|\/ad_left_|\/ad_entry_|\/statistics\.js\?|\/adv_horiz\.|\/ads300\.|\/js\/tracker\.js|\/ad\-exchange\.|\/wp\-js\/analytics\.|\-ad\.jpg\?|\/chitika\-ad\?|\/marketing\/js\/analytics\/|\/images\/adds\/|\.com\/log\?type|\/ad728x15\.|\/ad728x15_|\/stats\-tracking\.js|\/affiliate_member_banner\/|\.in\/ads\.|\.in\/ads\/|\/exports\/tour\/|\/internal\-ad\-|\.ws\/ads\/|\/adsx\/|\/ad\/files\/|\/ad_files\/|\-adsmanager\/|\/adsmanager\/|\/adgeo\/|\/js\/tracking\.js|\/files\/ad\-|\/files\/ad\/|_files\/ad\.|\/b3\.php\?img=|\/yandex\-metrica\-watch\/|\/ads\/zone\/|\/ads\?zone=|\/post\-ad\-|\/gravity\-beacon\.js|\.fr\/ads\.|\/corner\-ad\.|\/adtag\.|\/adtag\/|\/adtag\?|\/adtag_|\?adtag=|\/ad_multi_|\/ad_horiz\.|\/vs\-track\.js|\/adp\-pro\/|\/log_stats\.php\?|\/tracking_link_cookie\.|\/webmaster_ads\/|\/wp\-content\/uploads\/useful_banner_manager_banners\/|\/adv\.php|\/images\/bg_ad\/|\/Ad\/Oas\?|\$csp=worker\-src 'none',domain=estream\.to$flashx\.cc$flashx\.co$flashx\.co$streamango\.com$vidoza\.co$vidoza\.net$vidto\.me$vidto\.se$vidtudu\.com|\/ad\-hcm\.|\/assets\/uts\/|\-adv\-v1\/|\/aff_banner\/|_temp\/ad_|\/story_ad\.|\/ad\-blocker\.js|\/wp\-content\/plugins\/anti\-block\/|\-ad\-random\/|\/ad\/random_|\/addyn\/3\.0\/|\.hr\/ads\.|\-ads\-placement\.|\.com\/adv\/|\.com\/adv\?|\.com\/adv_|\/widget\/ad\/|_widget_ad\.|\/popad\-|\/popad\.|\/ad\/cross\-|\/all\/ad\/|\/stat\.php\?|\/ad_campaign\?|\/assets\/adv\/|\/rtt\-log\-data\?|\/partner\/transparent_pixel\-|\/reklam\-ads2\.|\.xyz\/ads\/|\/ads\.json\?|\.net\/affiliate\/|\?event=advert_|\/bi_affiliate\.js|\/Cookie\?merchant=|\/adz\/images\/|\/adx_flash\.|\/rcom\-video\-ads\.|\/AdvertAssets\/|\/images\/adz\-|\/images\/adz\/|\/md\.js\?country=|\/_30\/ads\/|\-ads\/oas\/|\/ads\/oas\-|\/ads\/oas\/|\/trackings\/addview\/|\/publisher\.ad\.|\/youtube\-track\-event_|\/adv_image\/|\/image\/adv\/|\-your\-ad\-here\-|\/tracker_czn\.tsp\?|\.tv\/adl\.|\/lib\/ad\.js|\/Article\-Ad\-|\/create\-lead\.js|\/addLinkerEvents\-std\.|\/ad\.min\.|\/cpx\-ad\.|\/tracking_add_ons\.|&admeld_|\/admeld\.|\/admeld\/|\/admeld_|=admeld&|\/context_ad\/|\/ad\-third\-party\/|\/websie\-ads\-|\/analytics\-assets\/|\/pub\/js\/ad\.|\/assets\/analytics\:|\/pagead\.|\/pagead\?|\/ad\/generate\?|\/generate_ad\.|\/adv_top\.|\-ads\/video\.|\/ads\/video\/|\/ads\/video_|\-load\-advert\.|\/250x250\-adverts\.|\/client\-event\-logger\.|\/impressions\/log\?|\/affiliates\/contextual\.|\/affiliate\/ads\/|\/active\-ad\-|\/pickle\-adsystem\/|\/adzonesidead\.|\/ad_rotation\.|\/nd_affiliate\.|\/adblock\.js|\/tracker\.json\.php\?|\/affiliate\.linker\/|\/affiliate\.1800flowers\.|\/affiliate\/displayWidget\?|\/ads\/branding\/|\/ad\/timing\.|&adsize=|\?adsize=|\/share\/ads\/|\/advpreload\.|\/affiliate\/small_banner\/|\/affiliate_show_banner\.|\/affiliate\-assets\/banner\/|\/admin\/banners\/|\/mail_tracking\-cg\.php|\/adv\/topBanners\.|\/ad\/display\.php|\/adv\/bottomBanners\.|\/adclixad\.|\/adreload\.|\/adreload\?|\/ads\-admin\.|\/3rd\-party\-stats\/|\/assets\/ad\-|\/assets\/ad\/|\/ip\-advertising\/|\/libs\/tracker\.js|\/wp\-content\/plugins\/deadblocker\/|\/ad\-builder\.|\/adblock\-relief\/|\/ads\/navbar\/|\/pixiedust\-build\.js|\/comscore_beacon\.|\/assets\/tracking\-|\/search\-cookie\.aspx\?|\/ads_openx_|\/ad_medium_|\/sponsor%20banners\/|\/adifyad\.|\/adsmm\.dll\/|\/ads\/xtcore\.|\/tracked_ad\.|\/cookie\?affiliate|\/ads\/contextual\.|\/ads\/contextual_|\/ade\/baloo\.php|\-amazon\-ads\/|\/idevaffiliate\/banners\/|\/tracking\.js\?site_id=|_ads\-affiliates_|\-advertisement\/script\.|\-load\-ads\.|\/load\-ads$|\/CookieManager\-bdl\?|\/watch\?shu=|\/ads\.load\.|\/ads\/load\.|\/ads_load\/|\/adload\.|\/ads\-rec$|\/affiliate_base\/banners\/|\/ads\/head\.|\/wp\-content\/tracker\.|\/plugin\/trackEvents\.|\/watchonline_cookies\.|\/ad\-catalogue\-|\.ad\-ocad\.|\/ajax\-ad\/|\/ajax\/ad\/|\-gallery_ad\/|\/p2\/ads\/|\/hostkey\-ad\.|\/ad_fixedad\.|\/skype\-analytics\.|\.lazyload\-ad\-|\.lazyload\-ad\.|\/ad_lazyload\.|\/polopoly_fs\/ad\-|\/econa\-site\-search\-ajax\-log\-referrer\.php|\/ad_bannerPool\-|\/bannerfile\/ad_|\/ad\/superbanner\.|\/affiliate_show_iframe\.|\/im\-ad\/im\-rotator2\.|\/analytics\/urlTracker\.|\/comscore\/streamsense\.|\/pagead\/ads\?|\/ad_selectMainfixedad\.|\/trackingfilter\.json\?|\/flashtag\.txt\?Log=|\/websie\-ads3\.|\/ad\/ad2\/|\/ads\?cookie_|\/ads\-common\.|\/ads\/common\/|\-theme\/ads\/|_theme\/ads\/|\/tracking\/comscore\/|\/adv\/mjx\.|\/ads_ifr\.|\/ads\/generator\/|\/metrics\-VarysMetrics\.|\/tracker\/eventBatch\/|_stat\/addEvent\/|\/comscore_engine\.|\-analitycs\/\/metrica\.|\-analitycs\/metrica\.|\/sitetestclickcount\.enginedocument,script,subdocument|\/promo\/ad_|_promo_ad\/|\/ads\/creatives\/|\/adonis_event\/|\/ajaxLogger_tracking_|\?event=performancelogger\:|\/ga_no_cookie\.|\/ga_no_cookie_|\/ifolder\-ads\.|\/ad_mini_|\/ad\/js\/banner9232\.|\/init_cookie\.php\?|\-ads\/static\-|\/zalando\-ad\-|\/tracking\/setTracker\/|\/akamai_analytics_|\/include\/adsdaq|\/utm_cookie\.|\/GoogleAnalytics\?utmac=|\/ads\/menu_|\/ads\-scroller\-|\/ads\/original\/|\/ads\/inner_|\/inner\-ads\-|\/inner\-ads\/|\/google\-nielsen\-analytics\.|\/country_ad\.|\-advert_August\.|\.net\/flashads|\/scripts\/AdService_|\/adbrite\-|\/adbrite\.|\/adbrite\/|\/adbrite_|\/button_ads\/|\/gen_ads_|\/carousel_ads\.|\-ad\-reload\.|\-ad\-reload\/|\/wp\-content\/plugins\/bookingcom\-banner\-creator\/|\/log_zon_img\.|\-ad\-cube\.|\/json\/ad\/|\/ads_door\.|\/ads\/daily\.|\/ads\/daily_|\/ads\/adv\/|\/adv\/ads\/|\.refit\.ads\.|\/1912\/ads\/|\/ads\-mopub\?|\/ads\-nodep\.|\/ads\/\?QAPS_|\/ads\/getall|\/ads\/gray\/|\/ads\/like\/|\/ads\/smi24\-|\/bauer\.ads\.|\/img3\/ads\/|\/ispy\/ads\/|\/kento\-ads\-|\/libc\/ads\/|\/subs\-ads\/|\/wire\/ads\/|_html5\/ads\.|\-ads\-530x85\.|\-intern\-ads\/|\/ads\-inside\-|\/ads\-intros\.|\/ads\.compat\.|\/ads\/acctid=|\/ads\/banid\/|\/ads\/bilar\/|\/ads\/box300\.|\/ads\/oscar\/|\/ads\?spaceid|\/ads_codes\/|\/ads_medrec_|\/ads_patron\.|\/ads_sprout_|\/cmlink\/ads\-|\/cssjs\/ads\/|\/digest\/ads\.|\/doors\/ads\/|\/dpics\/ads\/|\/gawker\/ads\.|\/minify\/ads\-|\/skin3\/ads\/|\/webapp\/ads\-|\?ads_params=|\/ad_onclick\.|\/ads\/125l\.|\/ads\/125r\.|\/ads\/3002\.|\/ads\/468a\.|\/ads\/728b\.|\/ads\/mpu2\?|\/ads\/narf_|\/ads_gnm\/|\/ast\/ads\/|\/cvs\/ads\/|\/dxd\/ads\/|\/esi\/ads\/|\/inv\/ads\/|\/mda\-ads\/|\/sbnr\.ads\?|\/smb\/ads\/|\/ss3\/ads\/|\/tmo\/ads\/|\/tr2\/ads\/|\-contrib\-ads\.|\-contrib\-ads\/|\-ads\-Feature\-|\/aderlee_ads\.|\/ads\-reviews\-|\/ads\.jplayer\.|\/ads\/250x120_|\/ads\/300x120_|\/ads\/behicon\.|\/ads\/labels\/|\/ads\/pencil\/|\/ads\/square2\.|\/ads\/square3\.|\/cactus\-ads\/|\/campus\/ads\/|\/develop\/ads_|\/expandy\-ads\.|\/outline\-ads\-|\/uplimg\/ads\/|\/xfiles\/ads\/|\/bci\-ads\.|\/bci\-ads\/|\/ads\-sticker2\.|\/ads\.release\/|\/ads\/cnvideo\/|\/ads\/masthead_|\/ads\/mobiles\/|\/ads\/reskins\/|\/ads\/ringtone_|\/ads\/serveIt\/|\/central\/ads\/|\/cramitin\/ads_|\/gazette\/ads\/|\/hpcwire\/ads\/|\/jetpack\-ads\/|\/jsfiles\/ads\/|\/magazine\/ads\.|\/playerjs\/ads\.|\/taxonomy\-ads\.|\/ads\/webplayer\.|\/ads\/webplayer\?|\/ads\-mobileweb\-|\/ads\-segmentjs\.|\/ads\/leaderbox\.|\/ads\/proposal\/|\/ads\/sidedoor\/|\/ads\/swfobject\.|\/calendar\-ads\/|\/editable\/ads\/|\/releases\/ads\/|\/rule34v2\/ads\/|\/teaseimg\/ads\/|\-ads\-180x|\/ads\-arc\.|\/ads\-cch\-|\/ads\.w3c\.|\/ads\/cbr\.|\/ads\/im2\.|\/ads\?apid|\/ems\/ads\.|\/ia\/ads\/|\/old\/ads\-|\/ome\.ads\.|\/sni\-ads\.|\/tit\-ads\.|\/v7\/ads\/|\/vld\.ads\?|\-floorboard\-ads\/|\/ads\/htmlparser\.|\/ads\/postscribe\.|\/fileadmin\/ads\/|\/moneyball\/ads\/|\/permanent\/ads\/|\/questions\/ads\/|\/standalone\/ads\-|\/teamplayer\-ads\.|\/dmn\-advert\.|\/door\/ads\/|\/daily\/ads\/|\/tracker\/trackView\?|\/ads\/728x90above_|\/ads\/indexmarket\.|\/excellence\/ads\/|\/userimages\/ads\/|\-ads\/videoblaster\/|\/ads\-restrictions\.|\/ads\/displaytrust\.|\/ads\/scriptinject\.|\/ads\/writecapture\.|\/colorscheme\/ads\/|\/configspace\/ads\/|\/homeoutside\/ads\/|\/incotrading\-ads\/|\/ads\/checkViewport\.|\/ads\/welcomescreen\.|\/photoflipper\/ads\/|\/ads\-03\.|\/ads\/tso|\/ads\/generatedHTML\/|\/customcontrols\/ads\/|\/ads\/contextuallinks\/|\/ads\/elementViewability\.|\.ad\.json\?|\/watchit_ad\.|\/hosting\/ads\/|\/admvn_pop\.|\/qpon_big_ad|\/php\-stats\.phpjs\.php\?|\/php\-stats\.recjs\.php\?|\/json\/tracking\/|\/magic\-ads\/|\.html\?ad=|\.html\?ad_|\/html\/ad\.|\/html\/ad\/|\/ilivid\-ad\-|\/cgi\-sys\/count\.cgi\?df=|\/scripts\/tracking\.js|\/ads\/create_|\/ads\/popup\.|\/ads\/popup_|\-popup\-ads\-|\/track\.php\?referrer=|\/track_yt_vids\.|\/big\-ad\-switch\-|\/big\-ad\-switch\/|=big\-ad\-switch_|\/shared\/ads\.|\/shared\/ads\/|\/tncms\/ads\/|\/tracking\/digitalData\.|\/04\/ads\-|\/ads\-04\.|\/analys\/dep\/|\?eventtype=request&pid=|\/iva_thefilterjwanalytics\.|\/entry\.count\.image\?|\/xtanalyzer_roi\.|\/smedia\/ad\/|\/bsc_trak\.|\/ads\/drive\.|\/ad\-sovrn\.|\/tops\.ads\.|=get_preroll_cookie&|\/log\?sLog=|\/lead\-tracking\.|\/lead\-tracking\/|\/track_general_stat\.|\/ads\-blogs\-|\/addon\/analytics\/|\/trackv&tmp=|\/monetization\/ads\-|\/intermediate\-ad\-|\/adv_flash\.|\/adjs\.|\/adjs\/|\/adjs\?|\/adjs_|\/event\/rumdata\?|\/analiz\.php3\?|\/affiliate\-tracker\.|\/ads\-leader$|\/ads\-05\.|\/no\-adblock\/|\/event\?t=view&|\/comscore_stats\.|\/analytics\.json\?|\/ads\/exo_|\/adv\-scroll\-|\/adv\-scroll\.|\/gcui_vidtracker\/|\/atcode\-bannerize\/|\/fm\-ads1\.|\/ADV\/Custom\/|\-Results\-Sponsored\.|\/sbtracking\/pageview2\?|\/js_log_error\.|\/adbl_dtct\.|\.widgets\.ad\?|\/ads_event\.|\/AdCookies\.js|\/affiliate\-track\.|\/affiliate\.track\?|\/affiliate\/track\?|\/ima\/ads_|\/ads\.pbs|\/ads\/configuration\/|\/cookie\.crumb|\/meas\.ad\.pr\.|\/ads\-06\.|\-strip\-ads\-|\-ad\-gif\-|\/ad\.gif$|\/ad_gif\/|\/ad_gif_|_ad\.gif$|\/cookie\/visitor\/|\/buyer\/dyad\/|\/tracking\/track\.jsp\?|\/adv\.css\?|\/css\/adv\.|\/tracking\.relead\.|\/cross\-domain\-cookie\?|\/adm_tracking\.js|\/tracker\-ev\-sdk\.js|\/propagate_cookie\.|\/ad_system\/|\/showcode\?adids=|\/ads\-beacon\.|\/ads\/beacon\.|\/beacon\/ads\?|\/silver\/ads\/|\/stat\/eventManager\/|\/wp\-content\/mbp\-banner\/|\/ads\/select\/|\/ads\-01\.|\/logo\-ads\.|\/logo\/ads_|\/datacapture\/track|\/khan_analystics\.js|\/adv\.png|\/TILE_ADS\/|\/bftv\/ads\/|\/tracker\-config\.js|\-simple\-ads\.|\/seosite\-tracker\/|\/related\-ads\.|\/AdBlockDetection\/scriptForGA\.|\/javascript\/ads\.|\/javascript\/ads\/|\/styles\/ads\.|\/styles\/ads\/|\/dynamic\-ad\-|\/dynamic\-ad\/|\-adverts\.libs\.|\/tracking\-jquery\-shim\.|\/adv\.jsp|\/jkidd_cookies\?|\/ads\/motherless\.|\-ads\-master\/|\.am\/adv\/|\-ads\-tracking\-|\/ads_tracking\.|\/tracking\/ads\.|\/plugins\/status\.gif\?|\/traffic\-source\-cookie\.|\/traffic\-source\-cookie\/|\/track\-compiled\.js|\/Affiliate\-Banner\-|\/WritePartnerCookie\?|\/ad\-half_|\/analytics\.config\.js|\/banner\.ws\?|\/ajx\/ptrack\/|\/stats\/Logger\?|_stats\/Logger\?|\/fora_player_tracking\.|\/beacon\-cookie\.|\/ad%20banners\/|\/analytics\.bundled\.js|\/blogtotal_stats_|\/layout\/ads\/|\/A\-LogAnalyzer\/|\/tracking\/user_sync_widget\?|\/ad\/special\.|\/special_ad\.|\/Ad\/premium\/|\/ad\/p\/jsonp\?|\/ads\/profile\/|_ajax\/btrack\.php\?|\/track\/pix2\.asp\?|\/ads\/real_|\/ads_premium\.|\/gen\-ad\-|\/wp\-content\/plugins\/automatic\-social\-locker\/|\/ads\-rectangle\.|\/ads\/rectangle_|\/serv\.ads\.|\/stats\/adonis_|\/assets\/ads3\-|\/compiled\/ads\-|\/videolog\?vid=|\/affiliate\/ad\/|_affiliate_ad\.|\/2011\/ads\/|\-Advert\-JPEG\-|\/adim\.html\?ad|\/session\-tracker\/tracking\-|\-ads\/ad\-|\/ads\/ad\-|\/ads\/ad\.|\/ads\/ad_|\/ads_ad_|\/adlog\.php\?|\/ads_tracker\.|\/ads\/tracker\/|\/arms\-datacollectorjs\/|\/iframe_googleAnalytics|\/autotrack\.carbon\.js|\/ads\-07\.|\/ad\/extra\/|\/ad\/extra_|\/demo\/ads\/|\/track\/\?site|\/track\/site\/|\/Counter\.woa\/|\/jsc\/ads\.|\/stats_brand\.js|\/Javascripts\/Gilda\-May\.js|\/ads\.bundle\.|\/bundle\/ads\.|_sponsor_logic\.|\/statistics\/pageStat\/|\/ads\/freewheel\/|\/ads~adsize~|\/ads\/dhtml\/|_ads_v8\.|\/images2\/ads\/|\/status\-beacon\/|\/linktracking\.|\/storage\/adv\/|\/data\/ads\/|\/log\/jserr\.php|\-ads\.generated\.|\/3pt_ads\.|\/fea_ads\.|\/gtv_ads\.|\/qd_ads\/|\/ads_common_library\.|\/tracker\-r1\.js|\/ad\-callback\.|\/ez_aba_load\/|\/digg_ads\.|\/digg_ads_|\/eco_ads\/|\/flag_ads\.|\/ges_ads\/|\/m0ar_ads\.|\/miva_ads\.|_ads_Home\.|_ads_only&|\/statistics\/metrica\.|\/ad\/login\-|\/log\-ads\.|\/ads\/community\?|\/defer_ads\.|\/ifrm_ads\/|\/chorus_ads\.|\/torget_ads\.|_ads_single_|\/tracker\-setting\.js|_ads_updater\-|_rightmn_ads\.|_ads\/inhouse\/|\/inhouse_ads\/|\-Web\-Advert\.|\/ads\/track\.|\/ads\/track\/|\/track\.ads\/|\/included_ads\/|_ads_framework\.|\/Controls\/ADV\/|\/imagecache_ads\/|\/statistics\.aspx\?profile|\/adv\-bannerize\-|\/videostreaming_ads\.|_ads_contextualtargeting_|\/banners\/affiliate\/|\/jquery_FOR_AD\/|&adserv=|\.adserv\/|\/adserv\.|\/adserv\/|\/adserv_|\/ads\-config\.|\/ads\/config\/|\/ads_config\.|\/ignite\.partnerembed\.js|\/sponsors\/amg\.php\?|\-ad\-category\-|\?category=ad&|_admin\/ads\/|\/affiliate\/script\.php\?|\/amazon\-affiliate\-|\/xml\/ad\/|\/addstats\?callback=|\/mad\.aspx\?|\/players\/ads\.|\/vision\/ads\/|\/tracking\/addview\/|\/ads\/imbox\-|\/track\/read\/|\/wp\-click\-track\/|\/curveball\/ads\/|\/adm\/ad\/|\/banners\/ad10\.|\/banners\/ad11\.|\/ad\/window\.php\?|\/banner\/rtads\/|\/ad\/select\?|\/sitefiles\/ads\/|\/adblock\?id=|\/VisitLog\.asmx|\/ad_links\/|\/Click\?MQUrl=|\/ad\/no_cookie\?|\/ads\-02\.|\/securepubads\.|\/track\/(?=([\s\S]*?&CheckCookieId=))\1|\/impressions\/(?=([\s\S]*?\/track))\2|\/track\/(?=([\s\S]*?&siteurl=))\3|\/promoredirect\?(?=([\s\S]*?&campaign=))\4(?=([\s\S]*?&zone=))\5|\/images\/a\.gif\?(?=([\s\S]*?=))\6|\$csp=child\-src 'none'; frame\-src (?=([\s\S]*?; worker\-src 'none',domain=adfreetv\.ch$ddmix\.net$extratorrent\.cd$gofile\.io$hq\-porns\.com$intactoffers\.club$myfeed4u\.net$reservedoffers\.club$skyback\.ru$szukajka\.tv$thepiratebay\.cr$thepiratebay\.org$thepiratebay\.red$thevideo\.cc$thevideo\.ch$thevideo\.io$thevideo\.me$thevideo\.us$tvad\.me$vidoza\.net$vidup\.me))\7|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?cpx\.to))\8|\.us\/ad\/(?=([\s\S]*?\?))\9|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?mc\.yandex\.ru))\10|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?revcontent\.com))\11|\/cdn\-cgi\/pe\/bag\?r(?=([\s\S]*?cpalead\.com))\12|\/widgets\/adverts\/(?=([\s\S]*?\.))\13|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?contextual\.media\.net))\14|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?viglink\.com))\15|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?static\.getclicky\.com%2Fjs))\16|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?googleadservices\.com))\17|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?clkrev\.com))\18|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?nr\-data\.net))\19|\$csp=child\-src 'none'; frame\-src 'self' (?=([\s\S]*?; worker\-src 'none',domain=fileone\.tv$theappguruz\.com))\20|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?google\-analytics\.com%2Fanalytics\.js))\21|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?content\.ad))\22|\/cdn\-cgi\/pe\/bag\?r(?=([\s\S]*?pubads\.g\.doubleclick\.net))\23|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?cdn\.onthe\.io%2Fio\.js))\24|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?hs\-analytics\.net))\25|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?geoiplookup))\26|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?chartbeat\.js))\27|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?log\.outbrain\.com))\28|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?adsnative\.com))\29|\/cdn\-cgi\/pe\/bag2\?r\[\]=(?=([\s\S]*?eth\-pocket\.de))\30|\?AffiliateID=(?=([\s\S]*?&campaignsVpIds=))\31|\/\?com=visit(?=([\s\S]*?=record&))\32|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?bounceexchange\.com))\33|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.qualitypublishers\.com))\34|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.worldoffersdaily\.com))\35|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?eclkmpbn\.com))\36|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?eclkspsa\.com))\37|\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline',domain=fflares\.com$fileflares\.com$ibit\.to$piratbaypirate\.link$unblocktheship\.org$noobnoob\.rocks$indiaproxydl\.org$magnetbay\.eu$airproxyproxy\.pw$thepirate\.xyz$pietpiraat\.org$ahoypirate\.in$tpb\.tw$proxyindia\.net$thepiratebay\.blue$ahoypiratebaai\.eu$pirate\.bet$airproxytpb\.red$ikwildepiratebay\.xyz$piratebay\.tel$bayception\.pw$piratebay\.town$superbay\.link$thepiratebay\.kiwi$tpb\.one$baypirateproxy\.pw$rarbgmirrored\.org$rarbgmirror\.org$rarbg\.to$rarbgaccess\.org$rarbgmirror\.com$rarbgmirror\.xyz$rarbgproxy\.org$rarbgprx\.org$mrunlock\.pro$downloadpirate\.com$prox4you\.xyz$123unblock\.info$nocensor\.icu$unlockproject\.live$pirateproxy\.bet$thepiratebay\.vip$theproxybay\.net$thepiratebay\.tips$thepiratebay10\.org$prox1\.info$kickass\.vip$torrent9\.uno$torrentsearchweb\.ws$pirateproxy\.app$ukpass\.co$theproxybay\.net$thepiratebay\.tips$prox\.icu$proxybay\.ga$pirateproxy\.life$piratebae\.co\.uk$berhampore\-gateway\.ml$ikwilthepiratebay\.org$thepiratebay10\.org$bayfortaiwan\.online$unblockthe\.net$cruzing\.xyz))\38|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.codeonclick\.com))\39|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?az708531\.vo\.msecnd\.net))\40|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?zwaar\.org))\41|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.zergnet\.com))\42|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.amazonaws\.com))\43(?=([\s\S]*?secure\.js))\44|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?\.speednetwork1\.com))\45|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.content\-ad\.net))\46|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?revdepo\.com))\47|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?bnserving\.com))\48|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?linksmart\.com))\49|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?puserving\.com))\50|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?intellitxt\.com))\51|\/Redirect\.(?=([\s\S]*?MediaSegmentId=))\52|\/Log\?(?=([\s\S]*?&adID=))\53|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?scorecardresearch\.com))\54|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?\.google\-analytics\.com))\55|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?newrelic\.com))\56|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?adk2\.co))\57|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?pipsol\.net))\58|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?popcash\.net))\59|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?juicyads\.com))\60|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?mellowads\.com))\61|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?quantserve\.com))\62|\?zoneid=(?=([\s\S]*?_bannerid=))\63|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?adsrvmedia))\64|^javascript\:(?=([\s\S]*?window\.location))\65|=event&(?=([\s\S]*?_ads%))\66|\/affiliates\/(?=([\s\S]*?\/show_banner\.))\67|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?popads\.net))\68|\/g00\/(?=([\s\S]*?\/clientprofiler\/adb))\69|\/analytics\/(?=([\s\S]*?satellitelib\.js))\70|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?advertserve\.com))\71|\/impressions\/(?=([\s\S]*?\/creative\.png\?))\72|\/stats\/(?=([\s\S]*?\?category=))\73)/i;
var bad_url_parts_flag = 2601 > 0 ? true : false;  // test for non-zero number of rules
    
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
