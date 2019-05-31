// PAC (Proxy Auto Configuration) Filter from EasyList rules
// 
// Copyright (C) 2017 by Steven T. Smith <steve dot t dot smith at gmail dot com>, GPL
// https://github.com/essandess/easylist-pac-privoxy/
//
// PAC file created on Fri, 31 May 2019 20:31:22 GMT
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

// 1221 rules:
var bad_da_host_JSON = { "content.ad": null,
"webvisor.ru": null,
"exoclick.com": null,
"nastydollars.com": null,
"adziff.com": null,
"tsyndicate.com": null,
"sharethrough.com": null,
"amazon-adsystem.com": null,
"dianomi.com": null,
"moatads.com": null,
"ad.doubleclick.net": null,
"adsafeprotected.com": null,
"2mdn.net": null,
"doubleclick.net": null,
"go.megabanners.cf": null,
"pagead2.googlesyndication.com": null,
"ltassrv.com.s3.amazonaws.com": null,
"adchemy-content.com": null,
"admitad.com": null,
"serving-sys.com": null,
"g00.msn.com": null,
"coinad.com": null,
"adap.tv": null,
"ip-adress.com": null,
"dashad.io": null,
"optimizely.com": null,
"contentspread.net": null,
"adult.xyz": null,
"scorecardresearch.com": null,
"advertising.com": null,
"chartbeat.com": null,
"media.net": null,
"static.parsely.com": null,
"teads.tv": null,
"nuggad.net": null,
"click.aliexpress.com": null,
"log.pinterest.com": null,
"webtrekk.net": null,
"adnxs.com": null,
"imasdk.googleapis.com": null,
"smartadserver.com": null,
"movad.net": null,
"mxcdn.net": null,
"stroeerdigitalmedia.de": null,
"rlcdn.com": null,
"flashtalking.com": null,
"clicktale.net": null,
"adverserve.net": null,
"d11a2fzhgzqe7i.cloudfront.net": null,
"krxd.net": null,
"intelliad.de": null,
"visualwebsiteoptimizer.com": null,
"gitcdn.pw": null,
"crwdcntrl.net": null,
"banners.cams.com": null,
"hotjar.com": null,
"imglnkc.com": null,
"cm.g.doubleclick.net": null,
"ace.advertising.com": null,
"3lift.com": null,
"eclick.baidu.com": null,
"revcontent.com": null,
"adform.net": null,
"xxlargepop.com": null,
"quantserve.com": null,
"adition.com": null,
"cpx.to": null,
"mediaplex.com": null,
"bluekai.com": null,
"ad.proxy.sh": null,
"openx.net": null,
"lw2.gamecopyworld.com": null,
"adapd.com": null,
"bontent.powvideo.net": null,
"adfox.yandex.ru": null,
"bongacams.com": null,
"adx.kat.ph": null,
"traffic.focuusing.com": null,
"pixel.ad": null,
"adspayformymortgage.win": null,
"adc.stream.moe": null,
"ad.rambler.ru": null,
"firstclass-download.com": null,
"adv.drtuber.com": null,
"ebayobjects.com.au": null,
"trmnsite.com": null,
"yinmyar.xyz": null,
"pdheuryopd.loan": null,
"videoplaza.com": null,
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
"pos.baidu.com": null,
"ero-advertising.com": null,
"ads.yahoo.com": null,
"creativecdn.com": null,
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
"dnn506yrbagrg.cloudfront.net": null,
"gsp1.baidu.com": null,
"3wr110.xyz": null,
"log.outbrain.com": null,
"smallseotools.com": null,
"adk2.co": null,
"juicyads.com": null,
"adonweb.ru": null,
"metrics.brightcove.com": null,
"hornymatches.com": null,
"prpops.com": null,
"pixel.facebook.com": null,
"htmlhubing.xyz": null,
"onad.eu": null,
"adtrace.org": null,
"adcash.com": null,
"adexc.net": null,
"sexad.net": null,
"admedit.net": null,
"videoplaza.tv": null,
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
"adexchangeprediction.com": null,
"adnetworkperformance.com": null,
"liveadexchanger.com": null,
"ringtonematcher.com": null,
"superadexchange.com": null,
"downloadboutique.com": null,
"august15download.com": null,
"clicksor.com": null,
"bentdownload.com": null,
"adultadworld.com": null,
"admngronline.com": null,
"adxpansion.com": null,
"brucelead.com": null,
"venturead.com": null,
"ad-maven.com": null,
"ad4game.com": null,
"adplxmd.com": null,
"adrunnr.com": null,
"adxprtz.com": null,
"hpr.outbrain.com": null,
"ad131m.com": null,
"ad2387.com": null,
"adnium.com": null,
"adxite.com": null,
"alternads.info": null,
"adbma.com": null,
"adk2x.com": null,
"clickmngr.com": null,
"sharecash.org": null,
"xtendmedia.com": null,
"collector.contentexchange.me": null,
"clicktripz.com": null,
"widget.yavli.com": null,
"tracking-rce.veeseo.com": null,
"media-servers.net": null,
"888media.net": null,
"ad6media.fr": null,
"clickosmedia.com": null,
"tagcdn.com": null,
"bullads.net": null,
"kissmetrics.com": null,
"stats.bitgravity.com": null,
"click.scour.com": null,
"pwrads.net": null,
"whoads.net": null,
"brandreachsys.com": null,
"traffictraffickers.com": null,
"livepromotools.com": null,
"c4tracking01.com": null,
"adblade.com": null,
"perfcreatives.com": null,
"youradexchange.com": null,
"toroadvertisingmedia.com": null,
"mediaseeding.com": null,
"pgmediaserve.com": null,
"waframedia5.com": null,
"wigetmedia.com": null,
"ringtonepartner.com": null,
"bettingpartners.com": null,
"trafficholder.com": null,
"trafficforce.com": null,
"yieldtraffic.com": null,
"traffichaus.com": null,
"trafficshop.com": null,
"fpctraffic2.com": null,
"statsmobi.com": null,
"traktrafficflow.com": null,
"clicksvenue.com": null,
"terraclicks.com": null,
"clicksgear.com": null,
"onclickmax.com": null,
"poponclick.com": null,
"clickfuse.com": null,
"1phads.com": null,
"padsdel.com": null,
"popmyads.com": null,
"filthads.com": null,
"down1oads.com": null,
"affbuzzads.com": null,
"megapopads.com": null,
"epicgameads.com": null,
"hipersushiads.com": null,
"track.xtrasize.nl": null,
"onclickads.net": null,
"advmedialtd.com": null,
"adultadmedia.com": null,
"pointclicktrack.com": null,
"adcdnx.com": null,
"360adstrack.com": null,
"adglare.org": null,
"adswizz.com": null,
"adsrv4k.com": null,
"adsurve.com": null,
"adservme.com": null,
"adsupply.com": null,
"adserverplus.com": null,
"adscpm.net": null,
"adsmarket.com": null,
"pubads.g.doubleclick.net": null,
"shareasale.com": null,
"adexchangetracker.com": null,
"webcams.com": null,
"perfectmarket.com": null,
"reallifecam.com": null,
"freecontent.science": null,
"tubeadvertising.eu": null,
"freecontent.win": null,
"popshow.info": null,
"hm.baidu.com": null,
"urlcash.net": null,
"abctrack.bid": null,
"addmoredynamiclinkstocontent2convert.bid": null,
"advertiserurl.com": null,
"showcase.vpsboard.com": null,
"freecontent.trade": null,
"adfox.ru": null,
"xxxmatch.com": null,
"adport.io": null,
"bestforexplmdb.com": null,
"ad.smartclip.net": null,
"flcounter.com": null,
"patiskcontentdelivery.info": null,
"zymerget.win": null,
"tostega.ru": null,
"b.photobucket.com": null,
"adexchangemachine.com": null,
"adexchangegate.com": null,
"adhealers.com": null,
"admeerkat.com": null,
"adtgs.com": null,
"adm.shinobi.jp": null,
"aj1574.online": null,
"trackvoluum.com": null,
"hodling.science": null,
"flagads.net": null,
"plugin.ws": null,
"core.queerclick.com": null,
"popcash.net": null,
"pr-static.empflix.com": null,
"adright.co": null,
"iwebanalyze.com": null,
"adop.cc": null,
"adglare.net": null,
"histats.com": null,
"showcasead.com": null,
"9content.com": null,
"predictivadvertising.com": null,
"bestquickcontentfiles.com": null,
"fastclick.net": null,
"affiliate.mediatemple.net": null,
"hawkeye-data-production.sciencemag.org.s3-website-us-east-1.amazonaws.com": null,
"metricfast.com": null,
"adhome.biz": null,
"trackmytarget.com": null,
"vtracker.net": null,
"intab.xyz": null,
"topad.mobi": null,
"pc.thevideo.me": null,
"ozon.ru": null,
"jshosting.science": null,
"premium.naturalnews.tv": null,
"synthasite.net": null,
"affiliatesmedia.sbobet.com": null,
"jshosting.win": null,
"campanja.com": null,
"adboost.it": null,
"cookiescript.info": null,
"whatismyip.win": null,
"vserv.bc.cdn.bitgravity.com": null,
"indieclick.com": null,
"xs.mochiads.com": null,
"stats.ibtimes.co.uk": null,
"nextoptim.com": null,
"mellowads.com": null,
"mobtop.ru": null,
"bid.run": null,
"cdnmedia.xyz": null,
"ams.addflow.ru": null,
"webcounter.ws": null,
"googleadservices.com": null,
"webstats.com": null,
"popunderjs.com": null,
"hilltopads.net": null,
"cookietracker.cloudapp.net": null,
"codeonclick.com": null,
"afimg.liveperson.com": null,
"count.livetv.ru": null,
"adrotate.se": null,
"lightson.vpsboard.com": null,
"backlogtop.xyz": null,
"gocp.stroeermediabrands.de": null,
"affiliates-cdn.mozilla.org": null,
"bonzai.ad": null,
"ingame.ad": null,
"spider.ad": null,
"affiliatehub.skybet.com": null,
"affiliate.burn-out.tv": null,
"freewheel.mtgx.tv": null,
"analytics.us.archive.org": null,
"cklad.xyz": null,
"wmemsnhgldd.ru": null,
"gstaticadssl.l.google.com": null,
"s11clickmoviedownloadercom.maynemyltf.netdna-cdn.com": null,
"affiliate.iamplify.com": null,
"advserver.xyz": null,
"tracking.moneyam.com": null,
"topbinaryaffiliates.ck-cdn.com": null,
"tracklab.club": null,
"ufpcdn.com": null,
"vpnaffiliates.hidester.com": null,
"buythis.ad": null,
"popunder.ru": null,
"revimedia.com": null,
"trafficbroker.com": null,
"trafficstars.com": null,
"33traffic.com": null,
"trackingpro.pro": null,
"mytrack.pro": null,
"affiliate.mercola.com": null,
"getalinkandshare.com": null,
"youroffers.win": null,
"premiumstats.xyz": null,
"fdxstats.xyz": null,
"clickredirection.com": null,
"cloudset.xyz": null,
"onclicksuper.com": null,
"pulseonclick.com": null,
"topclickguru.com": null,
"onclickmega.com": null,
"video.oms.eu": null,
"adcfrthyo.tk": null,
"stat.radar.imgsmail.ru": null,
"affiliates.mozy.com": null,
"optimize-stats.voxmedia.com": null,
"partner.googleadservices.com": null,
"affiliates.mgmmirage.com": null,
"affiliates.goodvibes.com": null,
"affiliates.vpn.ht": null,
"affiliates.swappernet.com": null,
"affiliates.treasureisland.com": null,
"affiliates.londonmarketing.com": null,
"cdnaz.win": null,
"hostingcloud.loan": null,
"cache.worldfriends.tv": null,
"admo.tv": null,
"adne.tv": null,
"analytics.163.com": null,
"adverts.itv.com": null,
"performancetrack.info": null,
"ubertracking.info": null,
"affiliates.genealogybank.com": null,
"mobitracker.info": null,
"dstrack2.info": null,
"trackbar.info": null,
"u-ad.info": null,
"hostingcloud.racing": null,
"adfrog.info": null,
"adlinx.info": null,
"adalgo.info": null,
"ininmacerad.pro": null,
"adwalte.info": null,
"adplans.info": null,
"adlerbo.info": null,
"localytics.com": null,
"ewxssoad.bid": null,
"adm-vids.info": null,
"adproper.info": null,
"advsense.info": null,
"adofuokjj.bid": null,
"loljuduad.bid": null,
"rqmlurpad.bid": null,
"free-rewards.com-s.tv": null,
"adrtgbebgd.bid": null,
"scvonjdwad.bid": null,
"timonnbfad.bid": null,
"bannerexchange.com.au": null,
"advertisingvalue.info": null,
"analytics.blue": null,
"dashbida.com": null,
"toptracker.ru": null,
"ad.reachlocal.com": null,
"ad001.ru": null,
"deliberatelyvirtuallyshared.xyz": null,
"microad.net": null,
"ftrack.ru": null,
"bridgetrack.com": null,
"adbetclickin.pink": null,
"affiliate.resellerclub.com": null,
"advertur.ru": null,
"advombat.ru": null,
"advertone.ru": null,
"chinagrad.ru": null,
"totrack.ru": null,
"affiliateprogram.keywordspy.com": null,
"volgograd-info.ru": null,
"analytics00.meride.tv": null,
"hostingcloud.faith": null,
"pix.speedbit.com": null,
"cpaevent.ru": null,
"nextlandingads.com": null,
"zanox-affiliate.de": null,
"mtrack.nl": null,
"analytic.rocks": null,
"analytics.plex.tv": null,
"tracker.azet.sk": null,
"analytics.ifood.tv": null,
"analytics.ettoredelnegro.pro": null,
"googlerank.info": null,
"adz.zwee.ly": null,
"adzjzewsma.cf": null,
"clickpartoffon.xyz": null,
"adlure.biz": null,
"advnet.xyz": null,
"adnext.org": null,
"admaster.net": null,
"trackingoffer.info": null,
"lead.im": null,
"tracker.revip.info": null,
"adlog.com.com": null,
"ads.cc": null,
"adsmws.cloudapp.net": null,
"skimresources.com": null,
"analytic.pho.fm": null,
"respond-adserver.cloudapp.net": null,
"analytics.carambatv.ru": null,
"tracking.vengovision.ru": null,
"textad.sexsearch.com": null,
"hostingcloud.bid": null,
"cfcdist.loan": null,
"ad.gt": null,
"blogads.com": null,
"affiliate.com": null,
"moevideo.net": null,
"tracking.hostgator.com": null,
"clarium.global.ssl.fastly.net": null,
"link.link.ru": null,
"ad.spielothek.so": null,
"videos.oms.eu": null,
"adsjudo.com": null,
"szzxtanwoptm.bid": null,
"img.bluehost.com": null,
"tracker.tiu.ru": null,
"adserved.net": null,
"log.ren.tv": null,
"clicktalecdn.sslcs.cdngc.net": null,
"taeadsnmbbkvpw.bid": null,
"blogscash.info": null,
"track.cooster.ru": null,
"livestats.la7.tv": null,
"advmaker.su": null,
"wstats.e-wok.tv": null,
"bannerbank.ru": null,
"nimiq.watch": null,
"fnro4yu0.loan": null,
"holexknw.loan": null,
"affiliates.spark.net": null,
"screencapturewidget.aebn.net": null,
"publicidad.net": null,
"adfill.me": null,
"track.revolvermarketing.ru": null,
"sessioncam.com": null,
"log.worldsoft-cms.info": null,
"xtracker.pro": null,
"contextads.net": null,
"post.rmbn.ru": null,
"silverads.net": null,
"sevenads.net": null,
"comscore.com": null,
"hit-pool.upscore.io": null,
"adxxx.org": null,
"static.kinghost.com": null,
"traffic-media.co.uk": null,
"cdnfile.xyz": null,
"adsnative.com": null,
"stats.qmerce.com": null,
"googleadapis.l.google.com": null,
"analytics.wetpaint.me": null,
"cpufan.club": null,
"popads.media": null,
"adnet.ru": null,
"vologda-info.ru": null,
"drowadri.racing": null,
"metrics.aviasales.ru": null,
"engine.gamerati.net": null,
"analytics.cmg.net": null,
"analytics.wildtangent.com": null,
"ad-vice.biz": null,
"hostingcloud.party": null,
"oas.luxweb.com": null,
"profile.bharatmatrimony.com": null,
"jqwww.download": null,
"arpelog.info": null,
"awstrack.me": null,
"affiliates.myfax.com": null,
"beacon.squixa.net": null,
"ad2adnetwork.biz": null,
"adten.eu": null,
"ihstats.cloudapp.net": null,
"jquery-uim.download": null,
"beacon.gutefrage.net": null,
"adpath.mobi": null,
"leadad.mobi": null,
"count.yandeg.ru": null,
"adwired.mobi": null,
"sniperlog.ru": null,
"speee-ad.akamaized.net": null,
"pleasedontslaymy.download": null,
"eiadsdmj.bid": null,
"addynamics.eu": null,
"analytics.proxer.me": null,
"torads.xyz": null,
"aimatch.com": null,
"nicoad.nicovideo.jp": null,
"affiliates.galapartners.co.uk": null,
"analyzer.qmerce.com": null,
"tracker2.apollo-mail.net": null,
"adxxx.me": null,
"adn.ebay.com": null,
"access-analyze.org": null,
"rlogoro.ru": null,
"zoomanalytics.co": null,
"pixel.xmladfeed.com": null,
"adnz.co": null,
"adro.co": null,
"sabin.free.fr": null,
"statistic.date": null,
"metartmoney.met-art.com": null,
"usenetnl.download": null,
"advise.co": null,
"ad.duga.jp": null,
"track.atom-data.io": null,
"analytics.gvim.mobi": null,
"adnext.fr": null,
"adcarem.co": null,
"hotlog.ru": null,
"warlog.ru": null,
"microad.jp": null,
"pixel.reddit.com": null,
"clcknads.pro": null,
"gandrad.org": null,
"porn-ad.org": null,
"adregain.ru": null,
"objects.tremormedia.com": null,
"layer-ad.org": null,
"experianmarketingservices.digital": null,
"adigniter.org": null,
"adaction.se": null,
"oas.skyscanner.net": null,
"analytics.iraiser.eu": null,
"hostingcloud.stream": null,
"powerad.ai": null,
"affiliates.lynda.com": null,
"gripdownload.co": null,
"eads.to": null,
"analytics.epi.es": null,
"relead.com": null,
"find-ip-address.org": null,
"visit.homepagle.com": null,
"affiliates.minglematch.com": null,
"affiliates.picaboocorp.com": null,
"hostingcloud.review": null,
"logxp.ru": null,
"spylog.ru": null,
"affiliates.franchisegator.com": null,
"adserve.ph": null,
"quantumws.net": null,
"ad.idgtn.net": null,
"ad.jamba.net": null,
"cdn.trafficexchangelist.com": null,
"livestats.matrix.it": null,
"advatar.to": null,
"buysellads.net": null,
"ad.pickple.net": null,
"xfast.host": null,
"webtrack.biz": null,
"analytics.rechtslupe.org": null,
"analytics.truecarbon.org": null,
"cloudflare.solutions": null,
"optimalroi.info": null,
"analyticapi.pho.fm": null,
"tkn.4tube.com": null,
"tracking.vid4u.org": null,
"analytics.codigo.se": null,
"monova.site": null,
"i2ad.jp": null,
"advg.jp": null,
"hostingcloud.date": null,
"hostingcloud.download": null,
"logz.ru": null,
"adinte.jp": null,
"aid-ad.jp": null,
"adnico.jp": null,
"affiliates.thrixxx.com": null,
"admatrix.jp": null,
"ad20.net": null,
"adv9.net": null,
"impact-ad.jp": null,
"abnad.net": null,
"adf01.net": null,
"adprs.net": null,
"adrsp.net": null,
"bf-ad.net": null,
"dynad.net": null,
"analytics.mailmunch.co": null,
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
"webts.adac.de": null,
"1e0y.xyz": null,
"hdat.xyz": null,
"hhit.xyz": null,
"ad-back.net": null,
"adgoi-1.net": null,
"adowner.net": null,
"bidhead.net": null,
"analytic.piri.net": null,
"adcount.in": null,
"hivps.xyz": null,
"avero.xyz": null,
"bh8yx.xyz": null,
"retag.xyz": null,
"bnbir.xyz": null,
"adc-serv.net": null,
"adbasket.net": null,
"addynamo.net": null,
"admagnet.net": null,
"intextad.net": null,
"onlyalad.net": null,
"cndhit.xyz": null,
"verata.xyz": null,
"acamar.xyz": null,
"alamak.xyz": null,
"pcruxm.xyz": null,
"adadvisor.net": null,
"adglamour.net": null,
"adtegrity.net": null,
"advertpay.net": null,
"augmentad.net": null,
"elasticad.net": null,
"networkad.net": null,
"analytics.paddle.com": null,
"janrain.xyz": null,
"elwraek.xyz": null,
"fyredet.xyz": null,
"patoris.xyz": null,
"albireo.xyz": null,
"analytics.archive.org": null,
"individuad.net": null,
"addcontrol.net": null,
"adcastplus.net": null,
"adtransfer.net": null,
"adverticum.net": null,
"content-ad.net": null,
"widgetlead.net": null,
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
"dfanalytics.dealerfire.com": null,
"ad-balancer.net": null,
"ad-delivery.net": null,
"dashboardad.net": null,
"manager.koocash.fr": null,
"tchhelpdmn.xyz": null,
"zapstorage.xyz": null,
"tripedrated.xyz": null,
"alltheladyz.xyz": null,
"adimpression.net": null,
"mataharirama.xyz": null,
"mobsoftffree.xyz": null,
"cruftexcision.xyz": null,
"admaya.in": null,
"admaza.in": null,
"admarketplace.net": null,
"inspiringsweater.xyz": null,
"adzmaza.in": null,
"honestlypopularvary.xyz": null,
"privilegebedroomlate.xyz": null,
"stabilityappointdaily.xyz": null,
"torads.me": null,
"brand.net": null,
"advertisingpath.net": null,
"adultcommercial.net": null,
"adultadvertising.net": null,
"trackingoffer.net": null,
"adzincome.in": null,
"adchannels.in": null,
"userlog.synapseip.tv": null,
"visitor-analytics.net": null,
"tracker2kss.eu": null,
"trackerodss.eu": null,
"fasttracktech.biz": null,
"googleadservicepixel.com": null,
"cnstats.cdev.eu": null,
"event.getblue.io": null,
"track2.me": null,
"freetracker.biz": null,
"ad.kissanime.io": null,
"content-offer-app.site": null,
"adultsense.org": null,
"internalredirect.site": null,
"advmaker.ru": null,
"stat.bilibili.tv": null,
"analytics.reyrey.net": null,
"gitcdn.site": null,
"analytics.edgekey.net": null,
"analytics.traidnt.net": null,
"ad.kisscartoon.io": null,
"redirections.site": null,
"crazyad.net": null,
"analytics.dvidshub.net": null,
"adtr.io": null,
"ker.pic2pic.site": null,
"analytics.witglobal.net": null,
"fairad.co": null,
"trackpath.biz": null,
"advertise.com": null,
"performanceanalyser.net": null,
"adless.io": null,
"adapex.io": null,
"adlive.io": null,
"adnami.io": null,
"softonic-analytics.net": null,
"yandex-metrica.ru": null,
"affiliates.bookdepository.com": null,
"analytics.industriemagazin.net": null,
"adboost.com": null,
"tracking.thehut.net": null,
"adverti.io": null,
"tracking.ehavior.net": null,
"tracking.listhub.net": null,
"knowlead.io": null,
"analytics-engine.net": null,
"tracking.wlscripts.net": null,
"statistics.infowap.info": null,
"landsraad.cc": null,
"adregain.com": null,
"trackword.net": null,
"adalliance.io": null,
"adexchange.io": null,
"accede.site": null,
"scoutanalytics.net": null,
"simpleanalytics.io": null,
"counter.gd": null,
"iptrack.biz": null,
"track.qcri.org": null,
"adtotal.pl": null,
"adnow.com": null,
"hs-analytics.net": null,
"track.kandle.org": null,
"monkeytracker.cz": null,
"stats.teledyski.info": null,
"analytics.urx.io": null,
"owlanalytics.io": null,
"analytics.arz.at": null,
"stat.social": null,
"sageanalyst.net": null,
"analyticsip.net": null,
"analytics.tio.ch": null,
"deals.buxr.net": null,
"trackingapi.cloudapp.net": null,
"img.servint.net": null,
"analytics.solidbau.at": null,
"admeira.ch": null,
"analytics.suggestv.io": null,
"mediatraffic.com": null,
"tracking.oe24.at": null,
"visitor-analytics.io": null,
"counter.webmasters.bpath.com": null,
"tracking.krone.at": null,
"beacon.nuskin.com": null,
"adplusplus.fr": null,
"beacon.tingyun.com": null,
"tracking.kurier.at": null,
"business.sharedcount.com": null,
"beacon.viewlift.com": null,
"beacon.riskified.com": null,
"tracking.novem.pl": null,
"humanclick.com": null,
"tracking.customerly.io": null,
"beacon.errorception.com": null,
"beacon.heliumnetwork.com": null,
"beacon.securestudies.com": null,
"cookies.reedbusiness.nl": null,
"timeslogtn.timesnow.tv": null,
"beacon.wikia-services.com": null,
"socialtrack.co": null,
"analytics.yola.net": null,
"affiliate.godaddy.com": null,
"images.criteo.net": null,
"qom006.site": null,
"count.rin.ru": null,
"webads.co.nz": null,
"beacon.mtgx.tv": null,
"bb-analytics.jp": null,
"tjblfqwtdatag.bid": null,
"spinbox.freedom.com": null,
"analytics-cms.whitebeard.me": null,
"advertica.ae": null,
"xvideosharing.site": null,
"promotiontrack.mobi": null,
"realclick.co.kr": null,
"socialtrack.net": null,
"tracker.mtrax.net": null,
"ad.cooks.com": null,
"ad.evozi.com": null,
"tags.cdn.circlesix.co": null,
"vihtori-analytics.fi": null,
"analytics.carambo.la": null,
"adku.co": null,
"eroticmix.blogspot.": null,
"etracker.de": null,
"video-ad-stats.googlesyndication.com": null,
"pixel.watch": null,
"ad.fnnews.com": null,
"host-go.info": null,
"smartoffer.site": null,
"adgoi.mobi": null,
"abbeyblog.me": null,
"stats.mos.ru": null,
"ad.icasthq.com": null,
"ad.vidaroo.com": null,
"ad.jamster.com": null,
"track.bluecompany.cl": null,
"ad.spreaker.com": null,
"filadmir.site": null,
"gctwh9xc.site": null,
"itempana.site": null,
"jfx61qca.site": null,
"less-css.site": null,
"1wzfew7a.site": null,
"ag2hqdyt.site": null,
"track.g-bot.net": null,
"hostip.info": null,
"stats.lifenews.ru": null,
"tracker.publico.pt": null,
"onlinereserchstatistics.online": null,
"adclear.net": null,
"ad.outsidehub.com": null,
"ad.reklamport.com": null,
"ad.lyricswire.com": null,
"googleme.eu": null,
"analytics.websolute.it": null,
"analytics.digitouch.it": null,
"ad.foxnetworks.com": null,
"visits.lt": null,
"stattds.club": null,
"ad.directmirror.com": null,
"track.redirecting2.net": null,
"cnstats.ru": null,
"w4statistics.info": null,
"ad.mesomorphosis.com": null,
"ad.theepochtimes.com": null,
"dom002.site": null,
"media.studybreakmedia.com": null,
"analytics-static.ugc.bazaarvoice.com": null,
"adip.ly": null,
"brandads.net": null,
"clkads.com": null,
"ad.iloveinterracial.com": null,
"tracker.streamroot.io": null,
"tracking.trovaprezzi.it": null,
"utrack.hexun.com": null,
"stat.ruvr.ru": null,
"epnt.ebay.com": null,
"lapi.ebay.com": null,
"tracking.conversionlab.it": null,
"analytics.matchbin.com": null,
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
"tracking.conversion-lab.it": null,
"k9anf8bc.webcam": null,
"ilapi.ebay.com": null,
"stat.tvigle.ru": null,
"webstat.no": null,
"stat.sputnik.ru": null,
"stat.pravmir.ru": null,
"beacon.ehow.com": null,
"stat.pladform.ru": null,
"affiligay.net": null,
"infinity-tracking.net": null,
"trackstarsengland.net": null,
"metrics.tbliab.net": null,
"stat.woman-announce.ru": null,
"trackadvertising.net": null,
"track.cordial.io": null,
"track.codepen.io": null,
"letsgoshopping.tk": null,
"track.mobicast.io": null,
"fan.twitch.tv": null,
"optimost.com": null,
"metrics.ctvdigital.net": null,
"adbit.biz": null,
"trackdiscovery.net": null,
"trackpromotion.net": null,
"google-rank.org": null,
"affil.mupromo.com": null,
"speee-ad.jp": null,
"click.aristotle.net": null,
"beacon.aimtell.com": null,
"tracetracking.net": null,
"air360tracker.net": null,
"avazutracking.net": null,
"track.derbund.ch": null,
"track.24heures.ch": null,
"trackonomics.net": null,
"tracker.euroweb.net": null,
"analytics.ladmedia.fr": null,
"an.yandex.ru": null,
"analysis.focalprice.com": null,
"counter.insales.ru": null,
"adorika.net": null,
"adsummos.net": null,
"analytics.rambla.be": null,
"opentracker.net": null,
"ppctracking.net": null,
"smartracker.net": null,
"trackedlink.net": null,
"roitracking.net": null,
"track.bernerzeitung.ch": null,
"affiliate.cx": null,
"analytics.belgacom.be": null,
"logger.su": null,
"clkdown.info": null,
"minexmr.stream": null,
"webtracker.jp": null,
"beead.net": null,
"windowne.info": null,
"e-webtrack.net": null,
"maxtracker.net": null,
"trackedweb.net": null,
"trackmyweb.net": null,
"video1404.info": null,
"private.camz.": null,
"expresided.info": null,
"solutionzip.info": null,
"buysellads.com": null,
"downlossinen.info": null,
"adserve.com": null,
"js.stroeermediabrands.de": null,
"contentdigital.info": null,
"mstracker.net": null,
"track-web.net": null,
"wisetrack.net": null,
"img.hostmonster.com": null,
"impressioncontent.info": null,
"trackword.biz": null,
"adclick.pk": null,
"seecontentdelivery.info": null,
"webcontentdelivery.info": null,
"zumcontentdelivery.info": null,
"inewcontentdelivery.info": null,
"requiredcollectfilm.info": null,
"analytics.rtbf.be": null,
"adlure.net": null,
"adku.com": null,
"gameads.com": null,
"trackcmp.net": null,
"tracktrk.net": null,
"zmctrack.net": null,
"log.idnes.cz": null,
"htl.bid": null,
"etology.com": null,
"log.nordot.jp": null,
"event.dkb.de": null,
"estrack.net": null,
"bbtrack.net": null,
"adsrv.us": null,
"chartbeat.net": null,
"webstat.net": null,
"arcadebannerexchange.org": null,
"trackmkxoffers.se": null,
"event-listener.air.tv": null,
"jumplead.io": null,
"jumplead.com": null,
"metric.inetcore.com": null,
"etracker.com": null,
"liwimgti.bid": null,
"track2.mycliplister.com": null,
"traffic.tc-clicks.com": null,
"log.mappy.net": null,
"exponderle.pro": null,
"g-content.bid": null,
"eimgxlsqj.bid": null,
"filenlgic.bid": null,
"fjmxpixte.bid": null,
"tracker.calameo.com": null,
"addlvr.com": null,
"track.parse.ly": null,
"track.sauce.ly": null,
"providence.voxmedia.com": null,
"track.veedio.it": null,
"bcoavtimgn.bid": null,
"feacamnliz.bid": null,
"ghizipjlsi.bid": null,
"axbpixbcucv.bid": null,
"arqxpopcywrr.bid": null,
"bjkookfanmxx.bid": null,
"nrwofsfancse.bid": null,
"hostingcloud.win": null,
"pmzktktfanzem.bid": null,
"yxwdppixvzxau.bid": null,
"data.gosquared.com": null,
"tracking.hrs.de": null,
"webads.nl": null,
"tracking.srv2.de": null,
"sponsoredby.me": null,
"track.cedsdigital.it": null,
"jstracker.com": null,
"tracking.linda.de": null,
"tracking.plinga.de": null,
"tracking.ladies.de": null,
"tracking.sport1.de": null,
"playerassets.info": null,
"analyticapi.piri.net": null,
"tracking.mvsuite.de": null,
"tracking.netbank.de": null,
"tracking.emsmobile.de": null,
"tracking.tchibo.de": null,
"adorika.com": null,
"tracking.promiflash.de": null,
"omoukkkj.stream": null,
"adstat.4u.pl": null,
"tracking.goodgamestudios.com": null,
"tracking.hannoversche.de": null,
"cdn1.pebx.pl": null,
"bitx.tv": null,
"laim.tv": null,
"tra.pmdstatic.net": null,
"locotrack.net": null,
"statistics.m0lxcdn.kukuplay.com": null,
"tracking.autoscout24.com": null,
"moneroocean.stream": null,
"webassembly.stream": null,
"tracking.gj-mobile-services.de": null,
"tracking.beilagen-prospekte.de": null,
"ijncw.tv": null,
"dawin.tv": null,
"affec.tv": null,
"e2yth.tv": null,
"ov8pc.tv": null,
"data.minute.ly": null,
"cdna.tremormedia.com": null,
"cashtrafic.info": null,
"rentracks.jp": null,
"webtracker.apicasystem.com": null,
"hodlers.party": null,
"intelensafrete.stream": null,
"klapenlyidveln.stream": null,
"analytics.30m.com": null,
"analytics.r17.com": null,
"analytics.21cn.com": null,
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
"analytics.artirix.com": null,
"analytics.cincopa.com": null,
"analytics.pinpoll.com": null,
"analytics.thenest.com": null,
"analytics.infobae.com": null,
"onhercam.com": null,
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
"adgoi.com": null,
"analytics.themarketiq.com": null,
"analytics.schoolwires.com": null,
"analytics.socialblade.com": null,
"analytics.whatculture.com": null,
"analytics.atomiconline.com": null,
"analytics.cohesionapps.com": null,
"analytics.midwesternmac.com": null,
"analytics.vanillaforums.com": null,
"analytics.ziftsolutions.com": null,
"analytics.apnewsregistry.com": null,
"analytics.hindustantimes.com": null,
"extend.tv": null,
"analytics.convertlanguage.com": null,
"nativeads.com": null,
"analytics.onlyonlinemarketing.com": null,
"analytics.strangeloopnetworks.com": null,
"analytics.disneyinternational.com": null,
"counter.nn.ru": null,
"webtracker.educationconnection.com": null,
"goredirect.party": null,
"adzoe.de": null,
"tracking.to": null,
"zaehler.tv": null,
"shoofle.tv": null,
"webstat.se": null,
"w5statistics.info": null,
"w9statistics.info": null,
"counter.amik.ru": null,
"counter.rian.ru": null,
"adrise.de": null,
"counter.pr-cy.ru": null,
"tracking.ustream.tv": null,
"a-counter.kiev.ua": null,
"adheart.de": null,
"adtraxx.de": null,
"adprovi.de": null,
"paid4ad.de": null,
"viedeo2k.tv": null,
"ad-apac.doubleclick.net": null,
"ad-emea.doubleclick.net": null,
"coinhive-proxy.party": null,
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
var bad_da_host_exact_flag = 1221 > 0 ? true : false;  // test for non-zero number of rules
    
// 3 rules as an efficient NFA RegExp:
var bad_da_host_RegExp = /^(?:[\w-]+\.)*?(?:analytics\-beacon\-(?=([\s\S]*?\.amazonaws\.com))\1|rcm(?=([\s\S]*?\.amazon\.))\2|images\.(?=([\s\S]*?\.criteo\.net))\3)/i;
var bad_da_host_regex_flag = 3 > 0 ? true : false;  // test for non-zero number of rules

// 294 rules:
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
"allmyvideos.net/player/ova-jw.swf": null,
"eageweb.com/stats.php": null,
"elb.amazonaws.com/small.gif": null,
"thefile.me/apu.php": null,
"turboimagehost.com/p1.js": null,
"wired.com/tracker.js": null,
"dpstatic.com/banner.png": null,
"cgmlab.com/tools/geotarget/custombanner.js": null,
"googletagservices.com/dcm/dcmads.js": null,
"piano-media.com/bucket/novosense.swf": null,
"skyrock.net/js/stats_blog.js": null,
"brightcove.com/1pix.gif": null,
"barclaycard.co.uk/cs/static/js/esurveys/esurveys.js": null,
"washingtonpost.com/rw/sites/twpweb/js/init/init.track-header-1.0.0.js": null,
"mercola.com/Assets/js/omniture/sitecatalyst/mercola_s_code.js": null,
"websitehome.co.uk/seoheap/cheap-web-hosting.gif": null,
"cafenews.pl/mpl/static/static.js": null,
"video44.net/gogo/yume-h.swf": null,
"ulogin.ru/js/stats.js": null,
"ge.com/sites/all/themes/ge_2012/assets/js/bin/s_code.js": null,
"csmonitor.com/extension/csm_base/design/standard/javascript/adobe/s_code.js": null,
"s-msn.com/s/js/loader/activity/trackloader.min.js": null,
"hitleap.com/assets/banner.png": null,
"blogsdna.com/wp-content/themes/blogsdna2011/images/advertisments.png": null,
"vodo.net/static/images/promotion/utorrent_plus_buy.png": null,
"cloudfront.net/scripts/cookies.js": null,
"playstation.com/pscomauth/groups/public/documents/webasset/community_secured_s_code.js": null,
"charter.com/static/scripts/mock/tracking.js": null,
"revisionworld.co.uk/sites/default/files/imce/Double-MPU2-v2.gif": null,
"tubepornclassic.com/js/111.js": null,
"snazzyspace.com/generators/viewer-counter/counter.php": null,
"webhostranking.com/images/bluehost-coupon-banner-1.gif": null,
"zylom.com/pixel.jsp": null,
"wheninmanila.com/wp-content/uploads/2014/02/DTC-Hardcore-Quadcore-300x100.gif": null,
"dexerto.com/app/uploads/2016/11/Gfuel-LemoNade.jpg": null,
"thumblogger.com/thumblog/top_banner_silver.js": null,
"wheninmanila.com/wp-content/uploads/2011/05/Benchmark-Email-Free-Signup.gif": null,
"csmonitor.com/extension/csm_base/design/csm_design/javascript/omniture/s_code.js": null,
"9msn.com.au/share/com/js/fb_google_intercept.js": null,
"nzbking.com/static/nzbdrive_banner.swf": null,
"nitrobahn.com.s3.amazonaws.com/theme/getclickybadge.gif": null,
"forms.aweber.com/form/styled_popovers_and_lightboxes.js": null,
"adimgs.t2b.click/assets/js/ttbir.js": null,
"fncstatic.com/static/all/js/geo.js": null,
"military.com/data/popup/new_education_popunder.htm": null,
"aeroplan.com/static/js/omniture/s_code_prod.js": null,
"aircanada.com/shared/common/sitecatalyst/s_code.js": null,
"gannett-cdn.com/appservices/partner/sourcepoint/sp-mms-client.js": null,
"phonearena.com/_track.php": null,
"watchuseek.com/site/forabar/zixenflashwatch.swf": null,
"yourtv.com.au/share/com/js/fb_google_intercept.js": null,
"adap.tv/redir/client/static/as3adplayer.swf": null,
"hotdeals360.com/static/js/kpwidgetweb.js": null,
"expressen.se/static/scripts/s_code.js": null,
"pimpandhost.com/static/html/iframe.html": null,
"baymirror.com/static/img/bar.gif": null,
"liveonlinetv247.com/images/muvixx-150x50-watch-now-in-hd-play-btn.gif": null,
"wheninmanila.com/wp-content/uploads/2014/04/zion-wifi-social-hotspot-system.png": null,
"jeuxvideo.com/contenu/medias/video/countv.php": null,
"ford.com/ngtemplates/ngassets/com/forddirect/ng/newMetrics.js": null,
"paypal.com/acquisition-app/static/js/s_code.js": null,
"sexvideogif.com/msn.js": null,
"sexier.com/services/adsredirect.ashx": null,
"skyrock.net/img/pix.gif": null,
"audiusa.com/us/brand/en.usertracking_javascript.js": null,
"naptol.com/usr/local/csp/staticContent/js/ga.js": null,
"ultimatewindowssecurity.com/securitylog/encyclopedia/images/allpartners.swf": null,
"dl-protect.com/pop.js": null,
"soe.com/js/web-platform/web-data-tracker.js": null,
"ford.com/ngtemplates/ngassets/ford/general/scripts/js/galleryMetrics.js": null,
"privacytool.org/AnonymityChecker/js/fontdetect.js": null,
"attorrents.com/static/images/download3.png": null,
"cloudfront.net/track.html": null,
"btkitty.org/static/images/880X60.gif": null,
"cdnplanet.com/static/rum/rum.js": null,
"libertyblitzkrieg.com/wp-content/uploads/2012/09/cc200x300.gif": null,
"dexerto.com/app/uploads/2016/11/SCUF-5-Discount-Dexerto-Below-Article.jpg": null,
"amazonaws.com/pmb-musics/download_itunes.png": null,
"emergencymedicalparamedic.com/wp-content/uploads/2011/12/anatomy.gif": null,
"saabsunited.com/wp-content/uploads/REALCAR-SAABSUNITED-5SEC.gif": null,
"btkitty.com/static/images/880X60.gif": null,
"ultimatewindowssecurity.com/images/banner80x490_WSUS_FreeTool.jpg": null,
"staticbucket.com/boost//Scripts/libs/flickity.js": null,
"vidyoda.com/fambaa/chnls/ADSgmts.ashx": null,
"shopping.com/sc/pac/sdc_widget_v2.0_proxy.js": null,
"streams.tv/js/bn5.js": null,
"addtoany.com/menu/transparent.gif": null,
"ibtimes.com/player/stats.swf": null,
"nih.gov/share/scripts/survey.js": null,
"better-explorer.com/wp-content/uploads/2013/07/hf.5.png": null,
"careerwebsite.com/distrib_pages/jobs.cfm": null,
"tpb.piraten.lu/static/img/bar.gif": null,
"johnbridge.com/vbulletin/images/tyw/cdlogo-john-bridge.jpg": null,
"razor.tv/site/servlet/tracker.jsp": null,
"watchuseek.com/media/longines_legenddiver.gif": null,
"static.tumblr.com/dhqhfum/WgAn39721/cfh_header_banner_v2.jpg": null,
"lexus.com/lexus-share/js/campaign_tracking.js": null,
"better-explorer.com/wp-content/uploads/2012/09/credits.png": null,
"shopify.com/track.js": null,
"quintcareers.4jobs.com/Common/JavaScript/functions.tracking.js": null,
"whatreallyhappened.com/webpageimages/banners/uwslogosm.jpg": null,
"downloadsmais.com/imagens/download-direto.gif": null,
"androidfilehost.com/libs/otf/stats.otf.php": null,
"crabcut.net/popup.js": null,
"ebizmbainc.netdna-cdn.com/images/tab_sponsors.gif": null,
"investegate.co.uk/Weblogs/IGLog.aspx": null,
"lightboxcdn.com/static/identity.html": null,
"taringa.net/ajax/track-visit.php": null,
"static.pes-serbia.com/prijatelji/zero.png": null,
"themag.co.uk/assets/BV200x90TOPBANNER.png": null,
"fileplanet.com/fileblog/sub-no-ad.shtml": null,
"watchseries.eu/images/download.png": null,
"technewsdaily.com/crime-stats/local_crime_stats.php": null,
"livetradingnews.com/wp-content/uploads/vamp_cigarettes.png": null,
"mnginteractive.com/live/js/omniture/SiteCatalystCode_H_22_1_NC.js": null,
"whitedolly.com/wcf/images/redbar/logo_neu.gif": null,
"desiretoinspire.net/storage/layout/royalcountessad.gif": null,
"healthcarejobsite.com/Common/JavaScript/functions.tracking.js": null,
"flashi.tv/histats.php": null,
"xbox-scene.com/crave/logo_on_white_s160.jpg": null,
"ibrod.tv/ib.php": null,
"imageteam.org/upload/big/2014/06/22/53a7181b378cb.png": null,
"images.military.com/pixel.gif": null,
"sexilation.com/wp-content/uploads/2013/01/Untitled-1.jpg": null,
"pimpandhost.com/images/pah-download.gif": null,
"webtutoriaux.com/services/compteur-visiteurs/index.php": null,
"ino.com/img/sites/mkt/click.gif": null,
"samsung.com/ph/nextisnow/files/javascript.js": null,
"hostingtoolbox.com/bin/Count.cgi": null,
"jappy.tv/i/wrbng/abb.png": null,
"jillianmichaels.com/images/publicsite/advertisingslug.gif": null,
"cardstore.com/affiliate.jsp": null,
"meanjin.com.au/static/images/sponsors.jpg": null,
"friday-ad.co.uk/endeca/afccontainer.aspx": null,
"saabsunited.com/wp-content/uploads/rbm21.jpg": null,
"saabsunited.com/wp-content/uploads/USACANADA.jpg": null,
"ewrc-results.com/images/horni_ewrc_result_banner3.jpg": null,
"washingtonpost.com/wp-srv/javascript/piggy-back-on-ads.js": null,
"statig.com.br/pub/setCookie.js": null,
"youwatch.org/vod-str.html": null,
"uploadshub.com/downloadfiles/download-button-blue.gif": null,
"cruisesalefinder.co.nz/affiliates.html": null,
"microsoft.com/getsilverlight/scripts/silverlight/SilverlightAtlas-MSCOM-Tracking.js": null,
"worldnow.com/global/tools/video/Namespace_VideoReporting_DW.js": null,
"webmd.com/dtmcms/live/webmd/PageBuilder_Assets/JS/oas35.js": null,
"arstechnica.com/dragons/breath.gif": null,
"myanimelist.net/static/logging.html": null,
"shareit.com/affiliate.html": null,
"picturevip.com/imagehost/top_banners.html": null,
"domainapps.com/assets/img/domain-apps.gif": null,
"qbn.com/media/static/js/ga.js": null,
"nbcudigitaladops.com/hosted/housepix.gif": null,
"cams.com/p/cams/cpcs/streaminfo.cgi": null,
"imgdino.com/gsmpop.js": null,
"greyorgray.com/images/Fast%20Business%20Loans%20Ad.jpg": null,
"watchuseek.com/media/clerc-final.jpg": null,
"pcgamesn.com/sites/default/files/SE4L.JPG": null,
"zipcode.org/site_images/flash/zip_v.swf": null,
"videobull.to/wp-content/themes/videozoom/images/gotowatchnow.png": null,
"mywot.net/files/wotcert/vipre.png": null,
"messianictimes.com/images/Jews%20for%20Jesus%20Banner.png": null,
"kau.li/yad.js": null,
"videoszoofiliahd.com/wp-content/themes/vz/js/p.js": null,
"youwatch.org/driba.html": null,
"youwatch.org/9elawi.html": null,
"youwatch.org/iframe1.html": null,
"kuiken.co/static/w.js": null,
"judgeporn.com/video_pop.php": null,
"syndication.visualthesaurus.com/std/vtad.js": null,
"gold-prices.biz/gold_trading_leader.gif": null,
"staticice.com.au/cgi-bin/stats.cgi": null,
"videobull.to/wp-content/themes/videozoom/images/stream-hd-button.gif": null,
"google-analytics.com/cx/api.js": null,
"wearetennis.com/img/common/bnp-logo.png": null,
"rednationonline.ca/Portals/0/derbystar_leaderboard.jpg": null,
"watchuseek.com/media/wus-image.jpg": null,
"pcgamesn.com/sites/default/files/Se4S.jpg": null,
"sofascore.com/geoip.js": null,
"devilgirls.co/images/devil.gif": null,
"makeagif.com/parts/fiframe.php": null,
"englishgrammar.org/images/30off-coupon.png": null,
"cbc.ca/video/bigbox.html": null,
"releaselog.net/uploads2/656d7eca2b5dd8f0fbd4196e4d0a2b40.jpg": null,
"lazygirls.info/click.php": null,
"rtlradio.lu/stats.php": null,
"ablacrack.com/popup-pvd.js": null,
"desiretoinspire.net/storage/layout/modmaxbanner.gif": null,
"file.org/fo/scripts/download_helpopt.js": null,
"letour.fr/img/v6/sprite_partners_2x.png": null,
"google-analytics.com/siteopt.js": null,
"washtimes.com/static/images/SelectAutoWeather_v2.gif": null,
"playomat.de/sfye_noscript.php": null,
"klm.com/travel/generic/static/js/measure_async.js": null,
"russellgrant.com/hostedsearch/panelcounter.aspx": null,
"publicdomaintorrents.info/srsbanner.gif": null,
"timesnow.tv/googlehome.cms": null,
"scientopia.org/public_html/clr_lympholyte_banner.gif": null,
"as.jivox.com/jivox/serverapis/getcampaignbysite.php": null,
"nih.gov/medlineplus/images/mplus_en_survey.js": null,
"24hourfitness.com/includes/script/siteTracking.js": null,
"johnbridge.com/vbulletin/images/tyw/wedi-shower-systems-solutions.png": null,
"kitguru.net/wp-content/wrap.jpg": null,
"uramov.info/wav/wavideo.html": null,
"piano-media.com/auth/index.php": null,
"momtastic.com/libraries/pebblebed/js/pb.track.js": null,
"serial.sw.cracks.me.uk/img/logo.gif": null,
"js.static.m1905.cn/pingd.js": null,
"lijit.com/adif_px.php": null,
"odnaknopka.ru/stat.js": null,
"prospects.ac.uk/assets/js/prospectsWebTrends.js": null,
"better-explorer.com/wp-content/uploads/2013/10/PoweredByNDepend.png": null,
"hwbot.org/banner.img": null,
"thevideo.me/mba/cds.js": null,
"watchfree.to/topright.php": null,
"alladultnetwork.tv/main/videoadroll.xml": null,
"watchop.com/player/watchonepiece-gao-gamebox.swf": null,
"fileom.com/img/downloadnow.png": null,
"atom-data.io/session/latest/track.html": null,
"watchseries.eu/js/csspopup.js": null,
"virginholidays.co.uk/_assets/js/dc_storm/track.js": null,
"witbankspurs.co.za/layout_images/sponsor.jpg": null,
"unblockedpiratebay.com/static/img/bar.gif": null,
"fantasti.cc/ajax/gw.php": null,
"publicdomaintorrents.info/grabs/hdsale.png": null,
"vipi.tv/ad.php": null,
"kleisauke.nl/static/img/bar.gif": null,
"script.idgentertainment.de/gt.js": null,
"merchantcircle.com/static/track.js": null,
"redtube.com/_status/pix.php": null,
"jivox.com/jivox/serverapis/getcampaignbyid.php": null,
"digitizor.com/wp-content/digimages/xsoftspyse.png": null,
"binsearch.info/iframe.php": null,
"euronews.com/media/farnborough/farnborough_wp.jpg": null,
"vbs.tv/tracker.html": null,
"forward.com/workspace/assets/newimages/amazon.png": null,
"swatchseries.to/bootstrap.min.js": null,
"scriptlance.com/cgi-bin/freelancers/ref_click.cgi": null,
"cash9.org/assets/img/banner2.gif": null,
"cclickvidservgs.com/mattel/cclick.js": null,
"mercuryinsurance.com/static/js/s_code.js": null,
"paper.li/javascripts/analytics.js": null,
"checker.openwebtorrent.com/digital-ocean.jpg": null,
"homepage-baukasten.de/cookie.php": null,
"filestream.me/requirements/images/cialis_generic.gif": null,
"24video.net/din_new6.php": null,
"mail.yahoo.com/mc/md.php": null,
"bongacash.com/tools/promo.php": null,
"monkeyquest.com/monkeyquest/static/js/ga.js": null,
"ltfm.ca/stats.php": null,
"twinsporn.net/images/free-penis-pills.png": null,
"xbooru.com/block/adblocks.js": null,
"filestream.me/requirements/images/ed.gif": null,
"rightmove.co.uk/ps/images/logging/timer.gif": null,
"bc.vc/images/megaload.gif": null,
"netdna-ssl.com/wp-content/uploads/2017/01/tla17janE.gif": null,
"netdna-ssl.com/wp-content/uploads/2017/01/tla17sepB.gif": null,
"oscars.org/scripts/wt_include1.js": null,
"oscars.org/scripts/wt_include2.js": null,
"hdfree.tv/ad.html": null,
"bc.vc/adbcvc.html": null,
"viralogy.com/javascript/viralogy_tracker.js": null };
var bad_da_hostpath_exact_flag = 294 > 0 ? true : false;  // test for non-zero number of rules
    
// 911 rules as an efficient NFA RegExp:
var bad_da_hostpath_RegExp = /^(?:[\w-]+\.)*?(?:doubleclick\.net\/adx\/|doubleclick\.net\/adj\/|piano\-media\.com\/uid\/|jobthread\.com\/t\/|pornfanplace\.com\/js\/pops\.|porntube\.com\/adb\/|quantserve\.com\/pixel\/|doubleclick\.net\/pixel|addthiscdn\.com\/live\/|baidu\.com\/pixel|doubleclick\.net\/ad\/|netdna\-ssl\.com\/tracker\/|adf\.ly\/_|imageshack\.us\/ads\/|firedrive\.com\/tools\/|freakshare\.com\/banner\/|adform\.net\/banners\/|amazonaws\.com\/analytics\.|adultfriendfinder\.com\/banners\/|baidu\.com\/ecom|facebook\.com\/tr|widgetserver\.com\/metrics\/|google\-analytics\.com\/plugins\/|veeseo\.com\/tracking\/|channel4\.com\/ad\/|chaturbate\.com\/affiliates\/|redtube\.com\/stats\/|sextronix\.com\/images\/|domaintools\.com\/partners\/|barnebys\.com\/widgets\/|google\.com\/analytics\/|view\.atdmt\.com\/partner\/|adultfriendfinder\.com\/javascript\/|yahoo\.com\/track\/|cloudfront\.net\/track|yahoo\.com\/beacon\/|4tube\.com\/iframe\/|visiblemeasures\.com\/log|cursecdn\.com\/banner\/|pop6\.com\/banners\/|google\-analytics\.com\/gtm\/js|pcwdld\.com\/wp\-content\/plugins\/wbounce\/|propelplus\.com\/track\/|wupload\.com\/referral\/|dditscdn\.com\/log\/|adultfriendfinder\.com\/go\/|mediaplex\.com\/ad\/js\/|imagetwist\.com\/banner\/|wtprn\.com\/sponsors\/|xvideos\-free\.com\/d\/|github\.com\/_stats|slashgear\.com\/stats\/|wired\.com\/event|photobucket\.com\/track\/|hothardware\.com\/stats\/|sex\.com\/popunder\/|siberiantimes\.com\/counter\/|healthtrader\.com\/banner\-|voyeurhit\.com\/contents\/content_sources\/|pornoid\.com\/contents\/content_sources\/|lovefilm\.com\/partners\/|xxvideo\.us\/ad728x15|xxxhdd\.com\/contents\/content_sources\/|topbucks\.com\/popunder\/|broadbandgenie\.co\.uk\/widget|powvideo\.net\/ban\/|livedoor\.com\/counter\/|pornalized\.com\/contents\/content_sources\/|primevideo\.com\/uedata\/|vodpod\.com\/stats\/|soufun\.com\/stats\/|baidu\.com\/billboard\/pushlog\/|zawya\.com\/ads\/|cnn\.com\/ad\-|fapality\.com\/contents\/content_sources\/|shareasale\.com\/image\/|msn\.com\/tracker\/|video\-cdn\.abcnews\.com\/ad_|soundcloud\.com\/event|appspot\.com\/stats|rapidgator\.net\/images\/pics\/|hstpnetwork\.com\/ads\/|fwmrm\.net\/ad\/|sawlive\.tv\/ad|static\.criteo\.net\/js\/duplo[^\w.%-]|sourceforge\.net\/log\/|videowood\.tv\/ads|adroll\.com\/pixel\/|conduit\.com\/\/banners\/|ad\.admitad\.com\/banner\/|secureupload\.eu\/banners\/|googlesyndication\.com\/sodar\/|googlesyndication\.com\/safeframe\/|red\-tube\.com\/popunder\/|hosting24\.com\/images\/banners\/|phncdn\.com\/iframe|sparklit\.com\/counter\/|daylogs\.com\/counter\/|gamestar\.de\/_misc\/tracking\/|chameleon\.ad\/banner\/|filecrypt\.cc\/p\.|videoplaza\.tv\/proxy\/tracker[^\w.%-]|nytimes\.com\/ads\/|twitter\.com\/i\/jot|spacash\.com\/popup\/|pan\.baidu\.com\/api\/analytics|liutilities\.com\/partners\/|addthis\.com\/live\/|youtube\.com\/pagead\/|vidzi\.tv\/mp4|girlfriendvideos\.com\/ad|keepvid\.com\/ads\/|ad\.atdmt\.com\/s\/|citygridmedia\.com\/ads\/|theporncore\.com\/contents\/content_sources\/|static\.criteo\.net\/images[^\w.%-]|chaturbate\.com\/creative\/|doubleclick\.net\/pfadx\/video\.marketwatch\.com\/|worldfree4u\.top\/banners\/|twitter\.com\/metrics|dailymotion\.com\/track\-|dailymotion\.com\/track\/|anysex\.com\/assets\/|shareaholic\.com\/analytics_|kqzyfj\.com\/image\-|jdoqocy\.com\/image\-|tkqlhce\.com\/image\-|ad\.doubleclick\.net\/ddm\/trackclk\/|cfake\.com\/images\/a\/|ad\.atdmt\.com\/e\/|hqq\.tv\/js\/betterj\/|trrsf\.com\/metrics\/|advfn\.com\/tf_|virool\.com\/widgets\/|ad\.admitad\.com\/fbanner\/|quora\.com\/_\/ad\/|ad\.atdmt\.com\/i\/img\/|mygaming\.co\.za\/news\/wp\-content\/wallpapers\/|tube18\.sex\/tube18\.|mochiads\.com\/srv\/|xhamster\.com\/ads\/|reevoo\.com\/track\/|howtogermany\.com\/banner\/|pornmaturetube\.com\/content\/|aliexpress\.com\/js\/beacon_|carbiz\.in\/affiliates\-and\-partners\/|livefyre\.com\/tracking\/|videoplaza\.com\/proxy\/distributor\/|doubleclick\.net\/pfadx\/ugo\.gv\.1up\/|andyhoppe\.com\/count\/|youtube\.com\/ptracking|video\.mediaset\.it\/polymediashowanalytics\/|fulltiltpoker\.com\/affiliates\/|sun\.com\/share\/metrics\/|rt\.com\/static\/img\/banners\/|static\.criteo\.com\/flash[^\w.%-]|amazon\.com\/clog\/|autotrader\.co\.za\/partners\/|questionmarket\.com\/static\/|youtube\-nocookie\.com\/gen_204|static\.criteo\.com\/images[^\w.%-]|thrixxx\.com\/affiliates\/|mtvnservices\.com\/metrics\/|ncrypt\.in\/images\/a\/|static\.game\-state\.com\/images\/main\/alert\/replacement\/|videowood\.tv\/pop2|hostgator\.com\/~affiliat\/cgi\-bin\/affiliates\/|ad\.mo\.doubleclick\.net\/dartproxy\/|supplyframe\.com\/partner\/|google\-analytics\.com\/collect|bristolairport\.co\.uk\/~\/media\/images\/brs\/blocks\/internal\-promo\-block\-300x250\/|femalefirst\.co\.uk\/widgets\/|banners\.friday\-ad\.co\.uk\/hpbanneruploads\/|phncdn\.com\/images\/banners\/|allmyvideos\.net\/js\/ad_|wishlistproducts\.com\/affiliatetools\/|amazonaws\.com\/publishflow\/|any\.gs\/visitScript\/|amazonaws\.com\/ownlocal\-|addthis\.com\/at\/|softpedia\-static\.com\/images\/aff\/|upsellit\.com\/custom\/|doubleclick\.net\/pfadx\/mc\.channelnewsasia\.com[^\w.%-]|pussycash\.com\/content\/banners\/|amazonaws\.com\/bo\-assets\/production\/banner_attachments\/|doubleclick\.net\/activity|akamai\.net\/chartbeat\.|ad\.atdmt\.com\/m\/|techkeels\.com\/creatives\/|bluehost\-cdn\.com\/media\/partner\/images\/|theolympian\.com\/static\/images\/weathersponsor\/|staticneo\.com\/neoassets\/iframes\/leaderboard_bottom\.|cdn77\.org\/tags\/|doubleclick\.net\/pfadx\/intl\.sps\.com\/|embed\.docstoc\.com\/Flash\.asmx\/StoreReffer|allanalpass\.com\/track\/|cloudfront\.net\/performable\/|betwaypartners\.com\/affiliate_media\/|express\.de\/analytics\/|doubleclick\.net\/adx\/wn\.nat\.|mrc\.org\/sites\/default\/files\/uploads\/images\/Collusion_Banner|bigrock\.in\/affiliate\/|urlcash\.org\/banners\/|ebaystatic\.com\/aw\/signin\/ebay\-signin\-toyota\-|doubleclick\.net\/pfadx\/nbcu\.nhl\.|doubleclick\.net\/pfadx\/nbcu\.nhl\/|doubleclick\.net\/pfadx\/blp\.video\/midroll|doubleclick\.net\/pfadx\/tmz\.video\.wb\.dart\/|publicbroadcasting\.net\/analytics\/|updatetube\.com\/iframes\/|singlehop\.com\/affiliates\/|tlavideo\.com\/affiliates\/|twitch\.tv\/track\/|mail\.ru\/count\/|obox\-design\.com\/affiliate\-banners\/|static\.twincdn\.com\/special\/script\.packed|metromedia\.co\.za\/bannersys\/banners\/|sitegiant\.my\/affiliate\/|beacons\.vessel\-static\.com\/xff|theseblogs\.com\/visitScript\/|sulia\.com\/papi\/sulia_partner\.js\/|doubleclick\.net\/pfadx\/bzj\.bizjournals\/|doubleclick\.net\/pfadx\/ndm\.tcm\/|browsershots\.org\/static\/images\/creative\/|doubleclick\.net\/pfadx\/gn\.movieweb\.com\/|doubleclick\.net\/xbbe\/creative\/vast|goldmoney\.com\/~\/media\/Images\/Banners\/|doubleclick\.net\/pfadx\/www\.tv3\.co\.nz|share\-online\.biz\/affiliate\/|hulkload\.com\/b\/|terra\.com\.br\/metrics\/|static\.twincdn\.com\/special\/license\.packed|doubleclick\.net\/pfadx\/miniclip\.midvideo\/|doubleclick\.net\/pfadx\/miniclip\.prevideo\/|filedownloader\.net\/design\/|h2porn\.com\/contents\/content_sources\/|dnsstuff\.com\/dnsmedia\/images\/ft\.banner\.|storage\.to\/affiliate\/|apkmaza\.net\/wp\-content\/uploads\/|chefkoch\.de\/counter|110\.45\.173\.103\/ad\/|e\-tailwebstores\.com\/accounts\/default1\/banners\/|ibtimes\.com\/banner\/|thebull\.com\.au\/admin\/uploads\/banners\/|imagecarry\.com\/down|groupon\.com\/tracking|pedestrian\.tv\/_crunk\/wp\-content\/files_flutter\/|drift\.com\/track|doubleclick\.net\/pfadx\/nbcu\.nbc\/|brettterpstra\.com\/wp\-content\/uploads\/|dnevnik\.si\/tracker\/|olark\.com\/track\/|camwhores\.tv\/banners\/|bruteforcesocialmedia\.com\/affiliates\/|doubleclick\.net\/pfadx\/tmg\.telegraph\.|debtconsolidationcare\.com\/affiliate\/tracker\/|usps\.com\/survey\/|vidible\.tv\/placement\/vast\/|thenude\.eu\/media\/mxg\/|amazon\.com\/gp\/yourstore\/recs\/|mail\.ru\/counter|expertreviews\.co\.uk\/widget\/|appinthestore\.com\/click\/|doubleclick\.net\/pfadx\/ddm\.ksl\/|1movies\.to\/site\/videoroller|homoactive\.tv\/banner\/|aerotime\.aero\/upload\/banner\/|yyv\.co\/track\/|gaccmidwest\.org\/uploads\/tx_bannermanagement\/|videos\.com\/click|filez\.cutpaid\.com\/336v|dota\-trade\.com\/img\/branding_|couptopia\.com\/affiliate\/|flixcart\.com\/affiliate\/|infibeam\.com\/affiliate\/|lawdepot\.com\/affiliate\/|seedsman\.com\/affiliate\/|doubleclick\.net\/pfadx\/ccr\.|freemoviestream\.xyz\/wp\-content\/uploads\/|epictv\.com\/sites\/default\/files\/290x400_|suite101\.com\/tracking\/|hottubeclips\.com\/stxt\/banners\/|dealextreme\.com\/affiliate_upload\/|newoxfordreview\.org\/banners\/ad\-|plugins\.longtailvideo\.com\/yourlytics|ppc\-coach\.com\/jamaffiliates\/|cnzz\.com\/stat\.|adm\.fwmrm\.net\/p\/mtvn_live\/|doubleclick\.net\/pfadx\/ng\.videoplayer\/|whozacunt\.com\/images\/banner_|morningstaronline\.co\.uk\/offsite\/progressive\-listings\/|petri\.co\.il\/wp\-content\/uploads\/banner1000x75_|petri\.co\.il\/wp\-content\/uploads\/banner700x475_|vivatube\.com\/upload\/banners\/|sacbee\.com\/static\/dealsaver\/|media\.domainking\.ng\/media\/|slack\.com\/beacon\/|thenude\.eu\/affiliates\/|dx\.com\/affiliate\/|knco\.com\/wp\-content\/uploads\/wpt\/|zap2it\.com\/wp\-content\/themes\/overmind\/js\/zcode\-|yea\.xxx\/img\/creatives\/|itweb\.co\.za\/logos\/|multiupload\.nl\/popunder\/|thesundaily\.my\/sites\/default\/files\/twinskyscrapers|nfl\.com\/assets\/images\/hp\-poweredby\-|pwpwpoker\.com\/images\/banners\/|sectools\.org\/shared\/images\/p\/|ru4\.com\/click|wonderlabs\.com\/affiliate_pro\/banners\/|creativecdn\.com\/pix\/|desert\.ru\/tracking\/|vator\.tv\/tracking\/|accuradio\.com\/static\/track\/|preisvergleich\.de\/setcookie\/|putpat\.tv\/tracking|mixpanel\.com\/track|celebstoner\.com\/assets\/components\/bdlistings\/uploads\/|videovalis\.tv\/tracking\/|babyblog\.ru\/pixel|punterlink\.co\.uk\/images\/storage\/siteban|media\.enimgs\.net\/brand\/files\/escalatenetwork\/|doubleclick\.net\/pfadx\/muzuoffsite\/|worddictionary\.co\.uk\/static\/\/inpage\-affinity\/|media\.complex\.com\/videos\/prerolls\/|hqq\.watch\/js\/betterj\/|vitalmtb\.com\/assets\/vital\.aba\-|kontextr\.eu\/content\/track|expekt\.com\/affiliates\/|swurve\.com\/affiliates\/|yahooapis\.com\/get\/Valueclick\/CapAnywhere\.getAnnotationCallback|axandra\.com\/affiliates\/|themis\-media\.com\/media\/global\/images\/cskins\/|blissful\-sin\.com\/affiliates\/|singlemuslim\.com\/affiliates\/|mangaupdates\.com\/affiliates\/|bruteforceseo\.com\/affiliates\/|graduateinjapan\.com\/affiliates\/|c21media\.net\/wp\-content\/plugins\/sam\-images\/|ians\.in\/iansad\/|optimum\.net\/utilities\/doubleclicktargeting|visa\.com\/logging\/logEvent|doubleclick\.net\/pfadx\/nfl\.|sapeople\.com\/wp\-content\/uploads\/wp\-banners\/|sdamgia\.ru\/img\/blockadblock_|wikipedia\.org\/beacon\/|inphonic\.com\/tracking\/|nspmotion\.com\/tracking\/|rbth\.ru\/widget\/|doubleclick\.net\/pfadx\/sugar\.poptv\/|myanimelist\.cdn\-dena\.com\/images\/affiliates\/|inhumanity\.com\/cdn\/affiliates\/|proxysolutions\.net\/affiliates\/|dpbolvw\.net\/image\-|anrdoezrs\.net\/image\-|wwe\.com\/sites\/all\/modules\/wwe\/wwe_analytics\/|zambiz\.co\.zm\/banners\/|ironsquid\.tv\/data\/uploads\/sponsors\/|nmap\.org\/shared\/images\/p\/|seclists\.org\/shared\/images\/p\/|getadblock\.com\/images\/adblock_banners\/|doubleclick\.net\/pfadx\/CBS\.|theday\.com\/assets\/images\/sponsorlogos\/|russian\-dreams\.net\/static\/js\/|iradio\.ie\/assets\/img\/backgrounds\/|ad2links\.com\/js\/|vpnarea\.com\/affiliate\/|dailymail\.co\.uk\/tracking\/|borrowlenses\.com\/affiliate\/|adyou\.me\/bug\/adcash|thereadystore\.com\/affiliate\/|kommersant\.uk\/banner_stats|casti\.tv\/adds\/|204\.140\.25\.247\/ads\/|ukcast\.tv\/adds\/|distrowatch\.com\/images\/kokoku\/|myiplayer\.eu\/ad|conde\.io\/beacon|youporn\.com\/watch_postroll\/|tehrantimes\.com\/banner\/|live\-porn\.tv\/adds\/|salemwebnetwork\.com\/Stations\/images\/SiteWrapper\/|trustedreviews\.com\/mobile\/widgets\/html\/promoted\-phones|tsite\.jp\/static\/analytics\/|jenningsforddirect\.co\.uk\/sitewide\/extras\/|popeoftheplayers\.eu\/ad|taboola\.com\/tb|mightydeals\.com\/widget|theatm\.info\/images\/|saabsunited\.com\/wp\-content\/uploads\/180x460_|saabsunited\.com\/wp\-content\/uploads\/werbung\-|lipsy\.co\.uk\/_assets\/images\/skin\/tracking\/|avito\.ru\/stat\/|hentaistream\.com\/wp\-includes\/images\/bg\-|nation\.sc\/images\/banners\/|talkphotography\.co\.uk\/images\/externallogos\/banners\/|timesinternet\.in\/ad\/|aftonbladet\.se\/blogportal\/view\/statistics|sextvx\.com\/static\/images\/tpd\-|citeulike\.org\/static\/campaigns\/|porn2blog\.com\/wp\-content\/banners\/|shinypics\.com\/blogbanner\/|freeporn\.to\/wpbanner\/|doubleclick\.net\/pfadx\/ctv\.spacecast\/|smn\-news\.com\/images\/banners\/|gameblog\.fr\/images\/ablock\/|doubleclick\.net\/pfadx\/csn\.|doubleclick\.net\/pfadx\/muzumain\/|cloudfront\.net\/analyticsengine\/|americanfreepress\.net\/assets\/images\/Banner_|whistleout\.com\.au\/imagelibrary\/ads\/wo_skin_|abplive\.in\/analytics\/|skroutz\.gr\/analytics\/|sweed\.to\/affiliates\/|ovpn\.to\/ovpn\.to\/banner\/|b2w\.io\/event\/|djmag\.co\.uk\/sites\/default\/files\/takeover\/|go\.com\/stat\/|eccie\.net\/buploads\/|brandcdn\.com\/pixel\/|euphonik\.dj\/img\/sponsors\-|spot\.im\/yad\/|uploaded\.to\/img\/public\/|ball2win\.com\/Affiliate\/|ehow\.com\/services\/jslogging\/log\/|pixazza\.com\/track\/|sysomos\.com\/track\/|customerlobby\.com\/ctrack\-|luminate\.com\/track\/|picbucks\.com\/track\/|targetspot\.com\/track\/|turnsocial\.com\/track\/|peggo\.tv\/ad\/|nijobfinder\.co\.uk\/affiliates\/|omsnative\.de\/tracking\/|desperateseller\.co\.uk\/affiliates\/|ziffstatic\.com\/jst\/zdvtools\.|bitbond\.com\/affiliate\-program\/|hqfooty\.tv\/ad|ejpress\.org\/img\/banners\/|va\.tawk\.to\/log|channel4\.com\/assets\/programmes\/images\/originals\/|geometria\.tv\/banners\/|agitos\.de\/content\/track|digitalsatellite\.tv\/banners\/|ask\.com\/servlets\/ulog|justporno\.tv\/ad\/|eventful\.com\/tools\/click\/url|cdn\.69games\.xxx\/common\/images\/friends\/|xscores\.com\/livescore\/banners\/|ximagehost\.org\/myman\.|webdesignerdepot\.com\/wp\-content\/plugins\/md\-popup\/|tamilwire\.org\/images\/banners3\/|worldradio\.ch\/site_media\/banners\/|lumfile\.com\/lumimage\/ourbanner\/|alooma\.io\/track\/|slide\.com\/tracker\/|1page\.co\.za\/affiliate\/|getreading\.co\.uk\/static\/img\/bg_takeover_|s\.holm\.ru\/stat\/|thefind\.com\/page\/sizelog|oasap\.com\/images\/affiliate\/|ed\-protect\.org\/cdn\-cgi\/apps\/head\/|tvducky\.com\/imgs\/graboid\.|nigeriafootball\.com\/img\/affiliate_|needle\.com\/pageload|djmag\.com\/sites\/default\/files\/takeover\/|carambo\.la\/analytics\/|dailyhome\.com\/leaderboard_banner|annistonstar\.com\/leaderboard_banner|relink\.us\/images\/|guru99\.com\/images\/adblocker\/|ziffstatic\.com\/jst\/zdsticky\.|swagmp3\.com\/cdn\-cgi\/pe\/|graboid\.com\/affiliates\/|movie2kto\.ws\/popup|itworld\.com\/slideshow\/iframe\/topimu\/|clickandgo\.com\/booking\-form\-widget|intercom\.io\/gtm_tracking\/|allmovieportal\.com\/dynbanner\.|reuters\.com\/tracker\/|examiner\.com\/sites\/all\/modules\/custom\/ex_stats\/|yotv\.co\/adds\/|piano\.io\/tracker\/|bits\.wikimedia\.org\/geoiplookup|chelsey\.co\.nz\/uploads\/Takeovers\/|amazonaws\.com\/fstrk\.net\/|theleader\.info\/banner|pcmall\.co\.za\/affiliates\/|sciencecareers\.org\/widget\/|watchuseek\.com\/media\/1900x220_|galleries\.bz\/track\/|frenchradiolondon\.com\/data\/carousel\/|early\-birds\.fr\/tracker\/|doubleclick\.net\/pfadx\/ssp\.kgtv\/|yandex\.ru\/cycounter|bbcchannels\.com\/workspace\/uploads\/|go2cdn\.org\/brand\/|vipbox\.tv\/js\/layer\-|traq\.li\/tracker\/|urbanvelo\.org\/sidebarbanner\/|4pda\.ru\/stat\/|journal\-news\.net\/annoyingpopup\/|s24cloud\.net\/metrics\/|dailymotion\.com\/logger\/|avira\.com\/site\/datatracking|anti\-scam\.org\/abanners\/|videogame\.it\/a\/logview\/|totalcmd\.pl\/img\/nucom\.|totalcmd\.pl\/img\/olszak\.|joblet\.jp\/javascripts\/|pixel\.indieclicktv\.com\/annonymous\/|concealednation\.org\/sponsors\/|gaccny\.com\/uploads\/tx_bannermanagement\/|ahk\-usa\.com\/uploads\/tx_bannermanagement\/|gaccwest\.com\/uploads\/tx_bannermanagement\/|safarinow\.com\/affiliate\-zone\/|gaccsouth\.com\/uploads\/tx_bannermanagement\/|karelia\.info\/counter\/|glam\.com\/gad\/|chaturbate\.com\/sitestats\/openwindow\/|arstechnica\.net\/public\/shared\/scripts\/da\-|adm24\.de\/hp_counter\/|doubleclick\.net\/json|daily\-mail\.co\.zm\/images\/banners\/|lgoat\.com\/cdn\/amz_|uploading\.com\/static\/banners\/|net\-parade\.it\/tracker\/|hentaihaven\.org\/wp\-content\/banners\/|static\.multiplayuk\.com\/images\/w\/w\-|amy\.gs\/track\/|dyo\.gs\/track\/|gamefront\.com\/wp\-content\/plugins\/tracker\/|dailymail\.co\.uk\/i\/pix\/ebay\/|attitude\.co\.uk\/images\/Music_Ticket_Button_|thelodownny\.com\/leslog\/ads\/|tshirthell\.com\/img\/affiliate_section\/|auto\.ru\/cookiesync\/|download\.bitdefender\.com\/resources\/media\/|tvbrowser\.org\/logo_df_tvsponsor_|oodle\.co\.uk\/event\/track\-first\-view\/|fapdick\.com\/uploads\/fap_|wank\.to\/partner\/|fapdick\.com\/uploads\/1fap_|moneywise\.co\.uk\/affiliate\/|uk\-mkivs\.net\/uploads\/banners\/|foxadd\.com\/addon\/upixel\/|youtube\.com\/user\/Blank|facebook\.com\/plugins\/|porntube\.com[^\w.%-](?=([\s\S]*?\/track))\1|facebook\.com[^\w.%-](?=([\s\S]*?\/tracking\.js))\2|bitgravity\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\3|youporn\.com[^\w.%-](?=([\s\S]*?\/tracker\.js))\4|clickfunnels\.com[^\w.%-](?=([\s\S]*?\/track))\5|ninemsn\.com\.au[^\w.%-](?=([\s\S]*?\.tracking\.udc\.))\6|cloudfront\.net(?=([\s\S]*?\/tracker\.js))\7|9msn\.com\.au[^\w.%-](?=([\s\S]*?\/tracking\/))\8|buzzfeed\.com[^\w.%-](?=([\s\S]*?\/tracker\.js))\9|gowatchit\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\10|reevoo\.com[^\w.%-](?=([\s\S]*?\/track\/))\11|skype\.com[^\w.%-](?=([\s\S]*?\/track_channel\.js))\12|svcs\.ebay\.com\/services\/search\/FindingService\/(?=([\s\S]*?[^\w.%-]affiliate\.tracking))\13|livefyre\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\14|forbes\.com[^\w.%-](?=([\s\S]*?\/track\.php))\15|goadv\.com[^\w.%-](?=([\s\S]*?\/track\.js))\16|msn\.com[^\w.%-](?=([\s\S]*?\/track\.js))\17|dealer\.com[^\w.%-](?=([\s\S]*?\/tracking\/))\18|zdf\.de[^\w.%-](?=([\s\S]*?\/tracking))\19|dealer\.com[^\w.%-](?=([\s\S]*?\/tracker\/))\20|staticwhich\.co\.uk\/assets\/(?=([\s\S]*?\/track\.js))\21|marketingpilgrim\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/trackur\.com\-))\22|euroleague\.tv[^\w.%-](?=([\s\S]*?\/tracking\.js))\23|azurewebsites\.net[^\w.%-](?=([\s\S]*?\/mnr\-mediametrie\-tracking\-))\24|partypoker\.com[^\w.%-](?=([\s\S]*?\/tracking\-))\25|vectorstock\.com[^\w.%-](?=([\s\S]*?\/tracking))\26|lemde\.fr[^\w.%-](?=([\s\S]*?\/tracking\/))\27|fyre\.co[^\w.%-](?=([\s\S]*?\/tracking\/))\28|gazzettaobjects\.it[^\w.%-](?=([\s\S]*?\/tracking\/))\29|volkswagen\-italia\.it[^\w.%-](?=([\s\S]*?\/tracking\/))\30|comparis\.ch[^\w.%-](?=([\s\S]*?\/Tracking\/))\31|akamai\.net[^\w.%-](?=([\s\S]*?\/sitetracking\/))\32|trackitdown\.net\/skins\/(?=([\s\S]*?_campaign\/))\33|typepad\.com[^\w.%-](?=([\s\S]*?\/stats))\34|kat2\.biz\/(?=([\s\S]*?))\35|kickass2\.biz\/(?=([\s\S]*?))\36|doubleclick\.net[^\w.%-](?=([\s\S]*?\/ad\/))\37|adf\.ly\/(?=([\s\S]*?\.php))\38|doubleclick\.net[^\w.%-](?=([\s\S]*?\/adj\/))\39|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/adawe\-))\40|images\-amazon\.com[^\w.%-](?=([\s\S]*?\/Analytics\-))\41|r18\.com[^\w.%-](?=([\s\S]*?\/banner\/))\42|hulkshare\.com[^\w.%-](?=([\s\S]*?\/adsmanager\.js))\43|allmyvideos\.net\/(?=([\s\S]*?%))\44|allmyvideos\.net\/(?=([\s\S]*?))\45|images\-amazon\.com\/images\/(?=([\s\S]*?\/banner\/))\46|torrentproject\.ch\/(?=([\s\S]*?))\47|rackcdn\.com[^\w.%-](?=([\s\S]*?\/analytics\.js))\48|openload\.co[^\w.%-](?=([\s\S]*?\/_))\49|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/adaptvjw5\-))\50|freebunker\.com[^\w.%-](?=([\s\S]*?\/pops\.js))\51|213\.174\.140\.76[^\w.%-](?=([\s\S]*?\/js\/msn\.js))\52|amazonaws\.com[^\w.%-](?=([\s\S]*?\/pageviews))\53|thevideo\.me\/(?=([\s\S]*?\.php))\54|liutilities\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\55|taboola\.com[^\w.%-](?=([\s\S]*?\/log\/))\56|xhcdn\.com[^\w.%-](?=([\s\S]*?\/ads_))\57|urlcash\.net\/random(?=([\s\S]*?\.php))\58|oload\.tv[^\w.%-](?=([\s\S]*?\/_))\59|blogsmithmedia\.com[^\w.%-](?=([\s\S]*?\/amazon_))\60|quantserve\.com[^\w.%-](?=([\s\S]*?\.swf))\61|freebunker\.com[^\w.%-](?=([\s\S]*?\/oc\.js))\62|ifilm\.com\/website\/(?=([\s\S]*?_skin_))\63|kitguru\.net\/wp\-content\/uploads\/(?=([\s\S]*?\-Skin\.))\64|yimg\.com[^\w.%-](?=([\s\S]*?\/sponsored\.js))\65|imgflare\.com[^\w.%-](?=([\s\S]*?\/splash\.php))\66|bestofmedia\.com[^\w.%-](?=([\s\S]*?\/beacons\/))\67|skypeassets\.com[^\w.%-](?=([\s\S]*?\/inclient\/))\68|thecatholicuniverse\.com[^\w.%-](?=([\s\S]*?\-ad\.))\69|i3investor\.com[^\w.%-](?=([\s\S]*?\/partner\/))\70|videogamesblogger\.com[^\w.%-](?=([\s\S]*?\/scripts\/takeover\.js))\71|paypal\.com[^\w.%-](?=([\s\S]*?\/pixel\.gif))\72|static\.(?=([\s\S]*?\.criteo\.net\/js\/duplo[^\w.%-]))\73|thevideo\.me\/(?=([\s\S]*?_))\74|redtubefiles\.com[^\w.%-](?=([\s\S]*?\/banner\/))\75|meetlocals\.com[^\w.%-](?=([\s\S]*?popunder))\76|cloudzer\.net[^\w.%-](?=([\s\S]*?\/banner\/))\77|tumblr\.com[^\w.%-](?=([\s\S]*?\/sponsored_))\78|tumblr\.com[^\w.%-](?=([\s\S]*?_sponsored_))\79|longtailvideo\.com[^\w.%-](?=([\s\S]*?\/ltas\-))\80|xhcdn\.com[^\w.%-](?=([\s\S]*?\/sponsor\-))\81|media\-imdb\.com[^\w.%-](?=([\s\S]*?\/affiliates\/))\82|avg\.com[^\w.%-](?=([\s\S]*?\/stats\.js))\83|widgetserver\.com[^\w.%-](?=([\s\S]*?\/image\.gif))\84|aolcdn\.com[^\w.%-](?=([\s\S]*?\/beacon\.min\.js))\85|facebook\.com\/ajax\/(?=([\s\S]*?\/log\.php))\86|speedcafe\.com[^\w.%-](?=([\s\S]*?\-banner\-))\87|static\.(?=([\s\S]*?\.criteo\.net\/images[^\w.%-]))\88|redtube\.com[^\w.%-](?=([\s\S]*?\/banner\/))\89|eweek\.com[^\w.%-](?=([\s\S]*?\/sponsored\-))\90|images\-amazon\.com\/images\/(?=([\s\S]*?\/ga\.js))\91|googleapis\.com[^\w.%-](?=([\s\S]*?\/gen_204))\92|freebunker\.com[^\w.%-](?=([\s\S]*?\/raw\.js))\93|imagefruit\.com[^\w.%-](?=([\s\S]*?\/pops\.js))\94|google\.com[^\w.%-](?=([\s\S]*?\/log))\95|idg\.com\.au\/images\/(?=([\s\S]*?_promo))\96|yimg\.com[^\w.%-](?=([\s\S]*?\/flash\/promotions\/))\97|arstechnica\.net[^\w.%-](?=([\s\S]*?\/sponsor\-))\98|adswizz\.com\/adswizz\/js\/SynchroClient(?=([\s\S]*?\.js))\99|24hourwristbands\.com\/(?=([\s\S]*?\.googleadservices\.com\/))\100|yimg\.com[^\w.%-](?=([\s\S]*?\/ywa\.js))\101|armorgames\.com[^\w.%-](?=([\s\S]*?\/banners\/))\102|postaffiliatepro\.com[^\w.%-](?=([\s\S]*?\/banners\/))\103|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/FME\-Red\-CAP\.jpg))\104|turner\.com[^\w.%-](?=([\s\S]*?\/ads\/))\105|thecatholicuniverse\.com[^\w.%-](?=([\s\S]*?\-advert\-))\106|widgetserver\.com[^\w.%-](?=([\s\S]*?\/quantcast\.swf))\107|googlesyndication\.com[^\w.%-](?=([\s\S]*?\/googlevideoadslibraryas3\.swf))\108|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/banner\.gif))\109|virginmedia\.com[^\w.%-](?=([\s\S]*?\/analytics\/))\110|pimpandhost\.com\/static\/i\/(?=([\s\S]*?\-pah\.jpg))\111|gfi\.com\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\-BlogBanner))\112|ibtimes\.com[^\w.%-](?=([\s\S]*?\/sponsor_))\113|johngaltfla\.com\/wordpress\/wp\-content\/uploads\/(?=([\s\S]*?\/TB2K_LOGO\.jpg))\114|phpbb\.com[^\w.%-](?=([\s\S]*?\/images\/hosting\/hostmonster\-downloads\.gif))\115|johngaltfla\.com\/wordpress\/wp\-content\/uploads\/(?=([\s\S]*?\/jmcs_specaialbanner\.jpg))\116|adamvstheman\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/AVTM_banner\.jpg))\117|lfcimages\.com[^\w.%-](?=([\s\S]*?\/partner\-))\118|financialsamurai\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/sliced\-alternative\-10000\.jpg))\119|newstatesman\.com\/sites\/all\/themes\/(?=([\s\S]*?_1280x2000\.))\120|yimg\.com[^\w.%-](?=([\s\S]*?\/fairfax\/))\121|imgbox\.com\/(?=([\s\S]*?\.html))\122|cdmagurus\.com\/img\/(?=([\s\S]*?\.gif))\123|amazonaws\.com[^\w.%-](?=([\s\S]*?\/Test_oPS_Script_Loads))\124|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/ibs\.orl\.news\/))\125|nichepursuits\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/long\-tail\-pro\-banner\.gif))\126|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/PW\-Ad\.jpg))\127|thechive\.files\.wordpress\.com[^\w.%-](?=([\s\S]*?\-wallpaper\-))\128|doubleclick\.net\/adx\/(?=([\s\S]*?\.NPR\.MUSIC\/))\129|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/DeadwoodStove\-PW\.gif))\130|opencurrency\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-aocs\-sidebar\-commodity\-bank\.png))\131|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/jihad\.jpg))\132|copblock\.org\/wp\-content\/uploads\/(?=([\s\S]*?\/covert\-handcuff\-key\-AD\-))\133|berush\.com\/images\/(?=([\s\S]*?_semrush_))\134|nufc\.com[^\w.%-](?=([\s\S]*?\/The%20Gate_NUFC\.com%20banner_%2016\.8\.13\.gif))\135|facebook\.com(?=([\s\S]*?\/impression\.php))\136|queermenow\.net\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\-Banner))\137|flixster\.com[^\w.%-](?=([\s\S]*?\/analytics\.))\138|thecommonsenseshow\.com\/siteupload\/(?=([\s\S]*?\/adsqmetals\.jpg))\139|uflash\.tv[^\w.%-](?=([\s\S]*?\/affiliates\/))\140|linkbird\.com\/static\/upload\/(?=([\s\S]*?\/banner\/))\141|mrc\.org[^\w.%-](?=([\s\S]*?\/Collusion_Banner300x250\.jpg))\142|allhiphop\.com\/site_resources\/ui\-images\/(?=([\s\S]*?\-conduit\-banner\.gif))\143|thehealthcareblog\.com\/files\/(?=([\s\S]*?\/American\-Resident\-Project\-Logo\-))\144|cooksunited\.co\.uk\/counter(?=([\s\S]*?\.php))\145|marijuanapolitics\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/icbc1\.png))\146|marijuanapolitics\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/icbc2\.png))\147|mydramalist\.info[^\w.%-](?=([\s\S]*?\/affiliates\/))\148|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Judge\-Lenny\-001\.jpg))\149|netbiscuits\.net[^\w.%-](?=([\s\S]*?\/analytics\/))\150|reddit\.com[^\w.%-](?=([\s\S]*?_sponsor\.png))\151|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Johnson\-Grow\-Lights\.gif))\152|db\.com[^\w.%-](?=([\s\S]*?\/stats\.js))\153|purpleporno\.com\/pop(?=([\s\S]*?\.js))\154|cloudfront\.net(?=([\s\S]*?\/trk\.js))\155|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/apmgoldmembership250x250\.jpg))\156|walshfreedom\.com[^\w.%-](?=([\s\S]*?\/liberty\-luxury\.png))\157|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?_250x150\.png))\158|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/team\.car\/))\159|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/team\.dal\/))\160|zoover\.(?=([\s\S]*?\/shared\/bannerpages\/darttagsbanner\.aspx))\161|bitcoinreviewer\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/banner\-luckybit\.jpg))\162|telegraphindia\.com[^\w.%-](?=([\s\S]*?\/banners\/))\163|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/app\.ytpwatch\.))\164|drivereasy\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/sidebar\-DriverEasy\-buy\.jpg))\165|rghost\.ru\/download\/a\/(?=([\s\S]*?\/banner_download_))\166|queermenow\.net\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\/banner))\167|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/embed\.ytpwatch\.))\168|nfl\.com[^\w.%-](?=([\s\S]*?\/page\-background\-image\.jpg))\169|adz\.lk[^\w.%-](?=([\s\S]*?_ad\.))\170|tipico\.(?=([\s\S]*?\/affiliate\/))\171|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.MTV\-Viacom\/))\172|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.NBCUNI\.COM\/))\173|ragezone\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/HV\-banner\-300\-200\.jpg))\174|youku\.com[^\w.%-](?=([\s\S]*?\/click\.php))\175|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/ccr\.newyork\.))\176|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.NBCUNIVERSAL\-CNBC\/))\177|techinsider\.net\/wp\-content\/uploads\/(?=([\s\S]*?\-300x500\.))\178|totallylayouts\.com[^\w.%-](?=([\s\S]*?\/users\-online\-counter\/online\.js))\179|player\.screenwavemedia\.com[^\w.%-](?=([\s\S]*?\/ova\-jw\.swf))\180|saf\.org\/wp\-content\/uploads\/(?=([\s\S]*?\/theGunMagbanner\.png))\181|ebaystatic\.com\/aw\/pics\/signin\/(?=([\s\S]*?_signInSkin_))\182|freebunker\.com[^\w.%-](?=([\s\S]*?\/layer\.js))\183|searchenginejournal\.com[^\w.%-](?=([\s\S]*?\/sponsored\-))\184|iimg\.in[^\w.%-](?=([\s\S]*?\/sponsor_))\185|thecommonsenseshow\.com\/siteupload\/(?=([\s\S]*?\/nightvisionadnew\.jpg))\186|preppersmallbiz\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/PSB\-Support\.jpg))\187|thehealthcareblog\.com\/files\/(?=([\s\S]*?\/THCB\-Validic\-jpg\-opt\.jpg))\188|grouponcdn\.com[^\w.%-](?=([\s\S]*?\/affiliate_widget\/))\189|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?_Side_Banner\.))\190|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?_Side_Banner_))\191|yimg\.com\/cv\/(?=([\s\S]*?\/billboard\/))\192|content\.ad\/Scripts\/widget(?=([\s\S]*?\.aspx))\193|activewin\.com[^\w.%-](?=([\s\S]*?\/blaze_static2\.gif))\194|saf\.org\/wp\-content\/uploads\/(?=([\s\S]*?\/women_guns192x50\.png))\195|video\.abc\.com[^\w.%-](?=([\s\S]*?\/promos\/))\196|s\-assets\.tp\-cdn\.com\/widgets\/(?=([\s\S]*?\/vwid\/))\197(?=([\s\S]*?\.html))\198|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/tsepulveda\-1\.jpg))\199|upcat\.custvox\.org\/survey\/(?=([\s\S]*?\/countOpen\.gif))\200|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/com\.ytpwatch\.))\201|data\.ninemsn\.com\.au\/(?=([\s\S]*?GetAdCalls))\202|static\.ow\.ly[^\w.%-](?=([\s\S]*?\/click\.gz\.js))\203|bestvpn\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/mosttrustedname_260x300_))\204|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.NBCUNIVERSAL\/))\205|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?_300x400_))\206|cannabisjobs\.us\/wp\-content\/uploads\/(?=([\s\S]*?\/OCWeedReview\.jpg))\207|maciverse\.mangoco\.netdna\-cdn\.com[^\w.%-](?=([\s\S]*?banner))\208|avito\.ru[^\w.%-](?=([\s\S]*?\/some\-pretty\-script\.js))\209|malaysiabay\.org[^\w.%-](?=([\s\S]*?creatives\.php))\210|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/sensi2\.jpg))\211|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/cannafo\.jpg))\212|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/WeedSeedShop\.jpg))\213|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/gorillabanner728\.gif))\214|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/dakine420\.png))\215|thepreparednessreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?_175x175\.jpg))\216|thepreparednessreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?_185x185\.jpg))\217|starofmysore\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\-karbonn\.))\218|upload\.ee\/image\/(?=([\s\S]*?\/B_descarga_tipo12\.gif))\219|sify\.com[^\w.%-](?=([\s\S]*?\/gads_))\220|images\-pw\.secureserver\.net[^\w.%-](?=([\s\S]*?_))\221(?=([\s\S]*?\.))\222|cardsharing\.info\/wp\-content\/uploads\/(?=([\s\S]*?\/ALLS\.jpg))\223|lfgcomic\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/PageSkin_))\224|heyjackass\.com\/wp\-content\/uploads\/(?=([\s\S]*?_300x225_))\225|nextbigwhat\.com\/wp\-content\/uploads\/(?=([\s\S]*?ccavenue))\226|capitolfax\.com\/wp\-content\/(?=([\s\S]*?ad\.))\227|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/team\.sd\/))\228|libero\.it[^\w.%-](?=([\s\S]*?\/counter\.php))\229|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/180_350\.))\230|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-250x250\.jpg))\231|prepperwebsite\.com\/wp\-content\/uploads\/(?=([\s\S]*?_250x250\.jpg))\232|sourcefed\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/netflix4\.jpg))\233|originalweedrecipes\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-Medium\.jpg))\234|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/free_ross\.jpg))\235|wp\.com\/adnetsreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?banner))\236|ebaystatic\.com\/aw\/signin\/(?=([\s\S]*?_wallpaper_))\237|googlesyndication\.com[^\w.%-](?=([\s\S]*?\/domainpark\.cgi))\238|saabsunited\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\-))\239|saabsunited\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\.))\240|saabsunited\.com\/wp\-content\/uploads\/(?=([\s\S]*?_banner_))\241|dailyanimation\.studio[^\w.%-](?=([\s\S]*?\/banners\.))\242|uniblue\.com[^\w.%-](?=([\s\S]*?\/affiliates\/))\243|capitolfax\.com\/wp\-content\/(?=([\s\S]*?Ad_))\244|pastime\.biz[^\w.%-](?=([\s\S]*?\/personalad))\245(?=([\s\S]*?\.jpg))\246|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/scrogger\.gif))\247|russiasexygirls\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/cb_))\248|thedailyblog\.co\.nz[^\w.%-](?=([\s\S]*?_Advert_))\249|survivaltop50\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/Survival215x150Link\.png))\250|raysindex\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/dolmansept2012flash\.swf))\251|sfstatic\.com[^\w.%-](?=([\s\S]*?\/js\/fl\.js))\252|mypbrand\.com\/wp\-content\/uploads\/(?=([\s\S]*?banner))\253|time4hemp\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/dynamic_banner_))\254|russiasexygirls\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/727x90))\255|947\.co\.za[^\w.%-](?=([\s\S]*?\-branding\.))\256|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?\/sbt\.gif))\257|morefree\.net\/wp\-content\/uploads\/(?=([\s\S]*?\/mauritanie\.gif))\258|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/xbt\-social\.png))\259|thejointblog\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-235x))\260|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.ABC\.com\/))\261|lego\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\262|srwww1\.com[^\w.%-](?=([\s\S]*?\/affiliate\/))\263|thepreparednessreview\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/250x125\-))\264|allmovie\.com[^\w.%-](?=([\s\S]*?\/affiliate_))\265|irctctourism\.com\/ttrs\/railtourism\/Designs\/html\/images\/tourism_right_banners\/(?=([\s\S]*?DealsBanner_))\266|tigerdirect\.com[^\w.%-](?=([\s\S]*?\/affiliate_))\267|freedom\.com[^\w.%-](?=([\s\S]*?\/analytics\/))\268|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/xbt\.jpg))\269|talktalk\.co\.uk[^\w.%-](?=([\s\S]*?\/log\.html))\270|thecompassionchronicles\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\-))\271|thecompassionchronicles\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-banner\.))\272|signup\.advance\.net[^\w.%-](?=([\s\S]*?affiliate))\273|newsonjapan\.com[^\w.%-](?=([\s\S]*?\/banner\/))\274|gmstatic\.net[^\w.%-](?=([\s\S]*?\/amazonbadge\.png))\275|xrad\.io[^\w.%-](?=([\s\S]*?\/hotspots\/))\276|dailyherald\.com[^\w.%-](?=([\s\S]*?\/contextual\.js))\277|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/allserviceslogo\.gif))\278|afcdn\.com[^\w.%-](?=([\s\S]*?\/ova\-jw\.swf))\279|mofomedia\.nl\/pop\-(?=([\s\S]*?\.js))\280|ebaystatic\.com[^\w.%-](?=([\s\S]*?\/motorswidgetsv2\.swf))\281|zombiegamer\.co\.za\/wp\-content\/uploads\/(?=([\s\S]*?\-skin\-))\282|videoly\.co[^\w.%-](?=([\s\S]*?\/event\/))\283|islamicity\.org[^\w.%-](?=([\s\S]*?\/sponsorship\-))\284|seedr\.ru[^\w.%-](?=([\s\S]*?\/stats\/))\285|dell\.com\/images\/global\/js\/s_metrics(?=([\s\S]*?\.js))\286|sillusions\.ws[^\w.%-](?=([\s\S]*?\/vpn\-banner\.gif))\287|dada\.net[^\w.%-](?=([\s\S]*?\/nedstat_sitestat\.js))\288|eteknix\.com\/wp\-content\/uploads\/(?=([\s\S]*?Takeover))\289|nature\.com[^\w.%-](?=([\s\S]*?\/marker\-file\.nocache))\290|hollyscoop\.com\/sites\/(?=([\s\S]*?\/skins\/))\291|gaystarnews\.com[^\w.%-](?=([\s\S]*?\-sponsor\.))\292|doubleclick\.net\/(?=([\s\S]*?\/pfadx\/lin\.))\293|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.ESPN\/))\294|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.muzu\/))\295|complexmedianetwork\.com[^\w.%-](?=([\s\S]*?\/toolbarlogo\.png))\296|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.BLIPTV\/))\297|doubleclick\.net\/pfadx\/(?=([\s\S]*?\/kidstv\/))\298|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/muzumain\/))\299|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/728_))\300|atlantafalcons\.com\/wp\-content\/(?=([\s\S]*?\/metrics\.js))\301|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.MCNONLINE\/))\302|doubleclick\.net\/pfadx\/(?=([\s\S]*?CBSINTERACTIVE\/))\303|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.VIACOMINTERNATIONAL\/))\304|doubleclick\.net\/pfadx\/(?=([\s\S]*?\.WALTDISNEYINTERNETGROU\/))\305|rapidfiledownload\.com[^\w.%-](?=([\s\S]*?\/btn\-input\-download\.png))\306|themittani\.com\/sites\/(?=([\s\S]*?\-skin))\307|wired\.com\/images\/xrail\/(?=([\s\S]*?\/samsung_layar_))\308|digitaltveurope\.net\/wp\-content\/uploads\/(?=([\s\S]*?_wallpaper_))\309|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/cloudbet_))\310|totallylayouts\.com[^\w.%-](?=([\s\S]*?\/visitor\-counter\/counter\.js))\311|dailyblogtips\.com\/wp\-content\/uploads\/(?=([\s\S]*?\.gif))\312|foxandhoundsdaily\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-AD\.gif))\313|vertical\-n\.de\/scripts\/(?=([\s\S]*?\/immer_oben\.js))\314|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-180x350\.))\315|sgtreport\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/180x350\.))\316|verticalnetwork\.de\/scripts\/(?=([\s\S]*?\/immer_oben\.js))\317|bizrate\.com[^\w.%-](?=([\s\S]*?\/survey_))\318|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/billpayhelp2\.png))\319|guns\.ru[^\w.%-](?=([\s\S]*?\/banners\/))\320|galatta\.com[^\w.%-](?=([\s\S]*?\/banners\/))\321|allposters\.com[^\w.%-](?=([\s\S]*?\/banners\/))\322|spotify\.com[^\w.%-](?=([\s\S]*?\/metric))\323|mmoculture\.com\/wp\-content\/uploads\/(?=([\s\S]*?\-background\-))\324|armorgames\.com[^\w.%-](?=([\s\S]*?\/siteskin\.css))\325|bassmaster\.com[^\w.%-](?=([\s\S]*?\/premier_sponsor_logo\/))\326|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?_270x312\.))\327|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?_1170x120\.))\328|ebaystatic\.com[^\w.%-](?=([\s\S]*?\/ScandalJS\-))\329|ebaystatic\.com[^\w.%-](?=([\s\S]*?\/ScandalSupportGFA\-))\330|nbr\.co\.nz[^\w.%-](?=([\s\S]*?\-WingBanner_))\331|yimg\.com\/cv\/(?=([\s\S]*?\/config\-object\-html5billboardfloatexp\.js))\332|i\.lsimg\.net[^\w.%-](?=([\s\S]*?\/sides_clickable\.))\333|amazon\.(?=([\s\S]*?\/ajax\/counter))\334|justsomething\.co\/wp\-content\/uploads\/(?=([\s\S]*?\-250x250\.))\335|between\-legs\.com[^\w.%-](?=([\s\S]*?\/banners\/))\336|llnwd\.net\/o28\/assets\/(?=([\s\S]*?\-sponsored\-))\337|aolcdn\.com\/os\/music\/img\/(?=([\s\S]*?\-skin\.jpg))\338|thessdreview\.com[^\w.%-](?=([\s\S]*?\/owc\-full\-banner\.jpg))\339|samoatimes\.co\.nz[^\w.%-](?=([\s\S]*?\/banner468x60\/))\340|doubleclick\.net[^\w.%-](?=([\s\S]*?\/pfadx\/ssp\.wews\/))\341|jdownloader\.org[^\w.%-](?=([\s\S]*?\/smbanner\.png))\342|hwscdn\.com[^\w.%-](?=([\s\S]*?\/brands_analytics\.js))\343|amazon\.(?=([\s\S]*?\/gp\/r\.html))\344|dreamscene\.org[^\w.%-](?=([\s\S]*?_Banner\.))\345|kvcr\.org[^\w.%-](?=([\s\S]*?\/sponsors\/))\346|star883\.org[^\w.%-](?=([\s\S]*?\/sponsors\.))\347|freecycle\.org[^\w.%-](?=([\s\S]*?\/sponsors\/))\348|cryptocoinsnews\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/ccn\.png))\349|upickem\.net[^\w.%-](?=([\s\S]*?\/affiliates\/))\350|agendize\.com[^\w.%-](?=([\s\S]*?\/counts\.jsp))\351|xxxgames\.biz[^\w.%-](?=([\s\S]*?\/sponsors\/))\352|tremormedia\.com[^\w.%-](?=([\s\S]*?\/tpacudeoplugin46\.swf))\353|lawprofessorblogs\.com\/responsive\-template\/(?=([\s\S]*?advert\.))\354|adprimemedia\.com[^\w.%-](?=([\s\S]*?\/video_report\/videoReport\.php))\355|adprimemedia\.com[^\w.%-](?=([\s\S]*?\/video_report\/attemptAdReport\.php))\356|dnsstuff\.com\/dnsmedia\/images\/(?=([\s\S]*?_banner\.jpg))\357|nzpages\.co\.nz[^\w.%-](?=([\s\S]*?\/banners\/))\358|sella\.co\.nz[^\w.%-](?=([\s\S]*?\/sella_stats_))\359|serials\.ws[^\w.%-](?=([\s\S]*?\/logo\.gif))\360|deepdotweb\.com\/wp\-content\/uploads\/(?=([\s\S]*?\/helix\.gif))\361|tv3\.ie[^\w.%-](?=([\s\S]*?\/sponsor\.))\362|hulkshare\.oncdn\.com[^\w.%-](?=([\s\S]*?\/removeads\.))\363|daily\-mail\.co\.zm[^\w.%-](?=([\s\S]*?_banner\.))\364|seeclickfix\.com[^\w.%-](?=([\s\S]*?\/text_widgets_analytics\.html))\365)/i;
var bad_da_hostpath_regex_flag = 911 > 0 ? true : false;  // test for non-zero number of rules
    
// 174 rules as an efficient NFA RegExp:
var bad_da_RegExp = /^(?:[\w-]+\.)*?(?:porntube\.com\/ads$|ads\.|adv\.|1337x\.to[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|banner\.|banners\.|torrentz2\.eu[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|affiliate\.|erotikdeal\.com\/\?ref=|affiliates\.|cloudfront\.net\/\?a=|synad\.|quantserve\.com\/pixel;|cursecdn\.com\/shared\-assets\/current\/anchor\.js\?id=|yahoo\.com\/p\.gif;|bluehost\.com\/web\-hosting\/domaincheckapi\/\?affiliate=|cloudfront\.net\/\?tid=|kickass2\.st[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|sweed\.to\/\?pid=|bittorrent\.am[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|oddschecker\.com\/clickout\.htm\?type=takeover\-|qualtrics\.com\/WRSiteInterceptEngine\/\?Q_Impress=|katcr\.co[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|nowwatchtvlive\.ws[^\w.%-]\$csp=script\-src 'self' |tube911\.com\/scj\/cgi\/out\.php\?scheme_id=|x1337x\.ws[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|torrentdownloads\.me[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|uploadproper\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|movies\.askjolene\.com\/c64\?clickid=|ipornia\.com\/scj\/cgi\/out\.php\?scheme_id=|watchsomuch\.info[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|api\.ticketnetwork\.com\/Events\/TopSelling\/domain=nytimes\.com|torrentfunk2\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|pirateiro\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|magnetdl\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|totalporn\.com\/videos\/tracking\/\?url=|torrentdownload\.ch[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|consensu\.org\/\?log=|ad\.atdmt\.com\/i\/go;|limetorrents\.info[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|yourbittorrent2\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline'|sponsorselect\.com\/Common\/LandingPage\.aspx\?eu=|t\-online\.de[^\w.%-](?=([\s\S]*?\/stats\.js\?track=))\1|tinypic\.com\/api\.php\?(?=([\s\S]*?&action=track))\2|fantasti\.cc[^\w.%-](?=([\s\S]*?\?ad=))\3|casino\-x\.com[^\w.%-](?=([\s\S]*?\?partner=))\4|allmyvideos\.net\/(?=([\s\S]*?=))\5|quantserve\.com[^\w.%-](?=([\s\S]*?[^\w.%-]a=))\6|exashare\.com[^\w.%-](?=([\s\S]*?&h=))\7|blacklistednews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\8|ad\.atdmt\.com\/i\/(?=([\s\S]*?=))\9|swatchseries\.to[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\10|acidcow\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\11|thevideo\.me\/(?=([\s\S]*?\:))\12|1movies\.is[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' 'unsafe\-eval' data\: (?=([\s\S]*?\.jwpcdn\.com ))\13(?=([\s\S]*?\.gstatic\.com ))\14(?=([\s\S]*?\.googletagmanager\.com ))\15(?=([\s\S]*?\.addthis\.com ))\16(?=([\s\S]*?\.google\.com))\17|phonearena\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\18|uptobox\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline' ))\19(?=([\s\S]*?\.gstatic\.com ))\20(?=([\s\S]*?\.google\.com ))\21(?=([\s\S]*?\.googleapis\.com))\22|iyfsearch\.com[^\w.%-](?=([\s\S]*?&pid=))\23|2hot4fb\.com\/img\/(?=([\s\S]*?\.gif\?r=))\24|watchcartoononline\.io[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\25|merriam\-webster\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\26|flirt4free\.com[^\w.%-](?=([\s\S]*?&utm_campaign))\27|plista\.com\/widgetdata\.php\?(?=([\s\S]*?%22pictureads%22%7D))\28|pornsharing\.com[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' 'unsafe\-eval' data\: (?=([\s\S]*?\.google\.com ))\29(?=([\s\S]*?\.gstatic\.com ))\30(?=([\s\S]*?\.google\-analytics\.com))\31|shortcuts\.search\.yahoo\.com[^\w.%-](?=([\s\S]*?&callback=yahoo\.shortcuts\.utils\.setdittoadcontents&))\32|media\.campartner\.com\/index\.php\?cpID=(?=([\s\S]*?&cpMID=))\33|wikia\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline' 'unsafe\-eval' ))\34(?=([\s\S]*?\.jwpsrv\.com ))\35(?=([\s\S]*?\.jwplayer\.com))\36|videogamesblogger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\37(?=([\s\S]*?\.gstatic\.com ))\38(?=([\s\S]*?\.google\.com ))\39(?=([\s\S]*?\.googleapis\.com ))\40(?=([\s\S]*?\.playwire\.com ))\41(?=([\s\S]*?\.facebook\.com ))\42(?=([\s\S]*?\.bootstrapcdn\.com ))\43(?=([\s\S]*?\.twitter\.com ))\44(?=([\s\S]*?\.spot\.im))\45|postimg\.cc\/image\/\$csp=script\-src 'self' (?=([\s\S]*? data\: blob\: 'unsafe\-eval'))\46|unblocked\.win[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\47|get\.(?=([\s\S]*?\.website\/static\/get\-js\?stid=))\48|sobusygirls\.fr[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-eval'))\49|eafyfsuh\.net[^\w.%-](?=([\s\S]*?\/\?name=))\50|bighealthreport\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\51(?=([\s\S]*?\.gstatic\.com ))\52(?=([\s\S]*?\.google\.com ))\53(?=([\s\S]*?\.googleapis\.com ))\54(?=([\s\S]*?\.playwire\.com ))\55(?=([\s\S]*?\.facebook\.com ))\56(?=([\s\S]*?\.bootstrapcdn\.com ))\57(?=([\s\S]*?\.yimg\.com))\58|linkbucks\.com[^\w.%-](?=([\s\S]*?\/\?))\59(?=([\s\S]*?=))\60|lijit\.com\/blog_wijits\?(?=([\s\S]*?=trakr&))\61|pockettactics\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\62|doubleclick\.net\/adj\/(?=([\s\S]*?\.collegehumor\/sec=videos_originalcontent;))\63|btkitty\.pet[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' (?=([\s\S]*?\.cloudflare\.com ))\64(?=([\s\S]*?\.googleapis\.com ))\65(?=([\s\S]*?\.jsdelivr\.net))\66|answerology\.com\/index\.aspx\?(?=([\s\S]*?=ads\.ascx))\67|freehostedscripts\.net[^\w.%-](?=([\s\S]*?\.php\?site=))\68(?=([\s\S]*?&s=))\69(?=([\s\S]*?&h=))\70|ifly\.com\/trip\-plan\/ifly\-trip\?(?=([\s\S]*?&ad=))\71|facebook\.com\/(?=([\s\S]*?\/plugins\/send_to_messenger\.php\?app_id=))\72|torrentz\.eu\/search(?=([\s\S]*?=))\73|solarmovie\.one[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\74|viralnova\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\75(?=([\s\S]*?\.gstatic\.com ))\76(?=([\s\S]*?\.google\.com ))\77(?=([\s\S]*?\.googleapis\.com ))\78(?=([\s\S]*?\.playwire\.com ))\79(?=([\s\S]*?\.facebook\.com ))\80(?=([\s\S]*?\.bootstrapcdn\.com))\81|rover\.ebay\.com\.au[^\w.%-](?=([\s\S]*?&cguid=))\82|shopify\.com\/(?=([\s\S]*?\/page\?))\83(?=([\s\S]*?&eventType=))\84|tipico\.(?=([\s\S]*?\?affiliateId=))\85|freebeacon\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? blob\: data\:))\86|barbwire\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\87(?=([\s\S]*?\.gstatic\.com ))\88(?=([\s\S]*?\.google\.com ))\89(?=([\s\S]*?\.googleapis\.com ))\90(?=([\s\S]*?\.playwire\.com ))\91(?=([\s\S]*?\.facebook\.com ))\92(?=([\s\S]*?\.bootstrapcdn\.com))\93|thehayride\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\94(?=([\s\S]*?\.gstatic\.com ))\95(?=([\s\S]*?\.google\.com ))\96(?=([\s\S]*?\.googleapis\.com ))\97(?=([\s\S]*?\.playwire\.com ))\98(?=([\s\S]*?\.facebook\.com ))\99(?=([\s\S]*?\.bootstrapcdn\.com))\100|wakingtimes\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\101(?=([\s\S]*?\.gstatic\.com ))\102(?=([\s\S]*?\.google\.com ))\103(?=([\s\S]*?\.googleapis\.com ))\104(?=([\s\S]*?\.playwire\.com ))\105(?=([\s\S]*?\.facebook\.com ))\106(?=([\s\S]*?\.bootstrapcdn\.com))\107|activistpost\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\108(?=([\s\S]*?\.gstatic\.com ))\109(?=([\s\S]*?\.google\.com ))\110(?=([\s\S]*?\.googleapis\.com ))\111(?=([\s\S]*?\.playwire\.com ))\112(?=([\s\S]*?\.facebook\.com ))\113(?=([\s\S]*?\.bootstrapcdn\.com))\114|allthingsvegas\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\115(?=([\s\S]*?\.gstatic\.com ))\116(?=([\s\S]*?\.google\.com ))\117(?=([\s\S]*?\.googleapis\.com ))\118(?=([\s\S]*?\.playwire\.com ))\119(?=([\s\S]*?\.facebook\.com ))\120(?=([\s\S]*?\.bootstrapcdn\.com))\121|survivalnation\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\122(?=([\s\S]*?\.gstatic\.com ))\123(?=([\s\S]*?\.google\.com ))\124(?=([\s\S]*?\.googleapis\.com ))\125(?=([\s\S]*?\.playwire\.com ))\126(?=([\s\S]*?\.facebook\.com ))\127(?=([\s\S]*?\.bootstrapcdn\.com))\128|thelibertydaily\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\129(?=([\s\S]*?\.gstatic\.com ))\130(?=([\s\S]*?\.google\.com ))\131(?=([\s\S]*?\.googleapis\.com ))\132(?=([\s\S]*?\.playwire\.com ))\133(?=([\s\S]*?\.facebook\.com ))\134(?=([\s\S]*?\.bootstrapcdn\.com))\135|visiontoamerica\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\136(?=([\s\S]*?\.gstatic\.com ))\137(?=([\s\S]*?\.google\.com ))\138(?=([\s\S]*?\.googleapis\.com ))\139(?=([\s\S]*?\.playwire\.com ))\140(?=([\s\S]*?\.facebook\.com ))\141(?=([\s\S]*?\.bootstrapcdn\.com))\142|comicallyincorrect\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\143(?=([\s\S]*?\.gstatic\.com ))\144(?=([\s\S]*?\.google\.com ))\145(?=([\s\S]*?\.googleapis\.com ))\146(?=([\s\S]*?\.playwire\.com ))\147(?=([\s\S]*?\.facebook\.com ))\148(?=([\s\S]*?\.bootstrapcdn\.com))\149|americasfreedomfighters\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\150(?=([\s\S]*?\.gstatic\.com ))\151(?=([\s\S]*?\.google\.com ))\152(?=([\s\S]*?\.googleapis\.com ))\153(?=([\s\S]*?\.playwire\.com ))\154(?=([\s\S]*?\.facebook\.com ))\155(?=([\s\S]*?\.bootstrapcdn\.com))\156|bulletsfirst\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.leadpages\.net ))\157(?=([\s\S]*?\.gstatic\.com ))\158(?=([\s\S]*?\.google\.com ))\159(?=([\s\S]*?\.googleapis\.com ))\160(?=([\s\S]*?\.playwire\.com ))\161(?=([\s\S]*?\.facebook\.com ))\162(?=([\s\S]*?\.bootstrapcdn\.com))\163|extremetech\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\164|doubleclick\.net\/pfadx\/(?=([\s\S]*?adcat=))\165|waybig\.com\/blog\/wp\-content\/uploads\/(?=([\s\S]*?\?pas=))\166|tipico\.com[^\w.%-](?=([\s\S]*?\?affiliateid=))\167|hop\.clickbank\.net\/(?=([\s\S]*?&transaction_id=))\168(?=([\s\S]*?&offer_id=))\169|amazon\.com\/gp\/(?=([\s\S]*?&linkCode))\170|skyscanner\.(?=([\s\S]*?\/slipstream\/applog$))\171|yifyddl\.movie[^\w.%-]\$csp=script\-src 'self' 'unsafe\-inline' (?=([\s\S]*?\.googleapis\.com))\172|menrec\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\173(?=([\s\S]*?\.google\.com ))\174(?=([\s\S]*?\.googleapis\.com ))\175(?=([\s\S]*?\.facebook\.com ))\176(?=([\s\S]*?\.bootstrapcdn\.com ))\177(?=([\s\S]*?\.twitter\.com ))\178(?=([\s\S]*?\.spot\.im))\179|ipatriot\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\180(?=([\s\S]*?\.google\.com ))\181(?=([\s\S]*?\.googleapis\.com ))\182(?=([\s\S]*?\.facebook\.com ))\183(?=([\s\S]*?\.bootstrapcdn\.com ))\184(?=([\s\S]*?\.twitter\.com ))\185(?=([\s\S]*?\.spot\.im))\186|clashdaily\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\187(?=([\s\S]*?\.google\.com ))\188(?=([\s\S]*?\.googleapis\.com ))\189(?=([\s\S]*?\.facebook\.com ))\190(?=([\s\S]*?\.bootstrapcdn\.com ))\191(?=([\s\S]*?\.twitter\.com ))\192(?=([\s\S]*?\.spot\.im))\193|dcdirtylaundry\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\194(?=([\s\S]*?\.google\.com ))\195(?=([\s\S]*?\.googleapis\.com ))\196(?=([\s\S]*?\.facebook\.com ))\197(?=([\s\S]*?\.bootstrapcdn\.com ))\198(?=([\s\S]*?\.twitter\.com ))\199(?=([\s\S]*?\.spot\.im))\200|thinkamericana\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\201(?=([\s\S]*?\.google\.com ))\202(?=([\s\S]*?\.googleapis\.com ))\203(?=([\s\S]*?\.facebook\.com ))\204(?=([\s\S]*?\.bootstrapcdn\.com ))\205(?=([\s\S]*?\.twitter\.com ))\206(?=([\s\S]*?\.spot\.im))\207|godfatherpolitics\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\208(?=([\s\S]*?\.google\.com ))\209(?=([\s\S]*?\.googleapis\.com ))\210(?=([\s\S]*?\.facebook\.com ))\211(?=([\s\S]*?\.bootstrapcdn\.com ))\212(?=([\s\S]*?\.twitter\.com ))\213(?=([\s\S]*?\.spot\.im))\214|libertyunyielding\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\215(?=([\s\S]*?\.google\.com ))\216(?=([\s\S]*?\.googleapis\.com ))\217(?=([\s\S]*?\.facebook\.com ))\218(?=([\s\S]*?\.bootstrapcdn\.com ))\219(?=([\s\S]*?\.twitter\.com ))\220(?=([\s\S]*?\.spot\.im))\221|conservativefiringline\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\222(?=([\s\S]*?\.google\.com ))\223(?=([\s\S]*?\.googleapis\.com ))\224(?=([\s\S]*?\.facebook\.com ))\225(?=([\s\S]*?\.bootstrapcdn\.com ))\226(?=([\s\S]*?\.twitter\.com ))\227(?=([\s\S]*?\.spot\.im))\228|onion\.ly[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\229|computerarts\.co\.uk\/(?=([\s\S]*?\.php\?cmd=site\-stats))\230|miniurls\.co[^\w.%-](?=([\s\S]*?\?ref=))\231|moviewatcher\.is[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\232|123unblock\.xyz[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\233|unblocked\.pet[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\234|truthuncensored\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*?\.gstatic\.com ))\235(?=([\s\S]*?\.google\.com ))\236(?=([\s\S]*?\.googleapis\.com ))\237(?=([\s\S]*?\.facebook\.com ))\238(?=([\s\S]*?\.bootstrapcdn\.com ))\239(?=([\s\S]*?\.twitter\.com ))\240(?=([\s\S]*?\.spot\.im))\241|machinenoveltranslation\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\242|fullmatchesandshows\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\243|nintendoeverything\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\244|textsfromlastnight\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\245|powerofpositivity\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\246|talkwithstranger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\247|readliverpoolfc\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\248|androidcentral\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\249|roadracerunner\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\250|tetrisfriends\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\251|thisisfutbol\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\252|almasdarnews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\253|colourlovers\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\254|convertfiles\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\255|investopedia\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\256|skidrowcrack\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\257|sportspickle\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\258|hiphopearly\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\259|readarsenal\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\260|kshowonline\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\261|moneyversed\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\262|thehornnews\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\263|torrentfunk\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\264|videocelts\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\265|britannica\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\266|csgolounge\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\267|grammarist\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\268|healthline\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\269|tworeddots\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\270|wuxiaworld\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\271|kiplinger\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\272|readmng\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\273|trifind\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\274|vidmax\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\275|debka\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\276|cts\.tradepub\.com\/cts4\/\?ptnr=(?=([\s\S]*?&tm=))\277|unblockall\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\278|online\.mydirtyhobby\.com[^\w.%-](?=([\s\S]*?\?naff=))\279|biology\-online\.org[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\280|ancient\-origins\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\281|asheepnomore\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\282|campussports\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\283|toptenz\.net[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\284|broadwayworld\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\285|prox4you\.pw[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\286|winit\.winchristmas\.co\.uk[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\287|blog\-rct\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\288|lolcounter\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\289|nsfwyoutube\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\290|thecelticblog\.com[^\w.%-]\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline'))\291)/i;
var bad_da_regex_flag = 174 > 0 ? true : false;  // test for non-zero number of rules
    
// 0 rules as an efficient NFA RegExp:
var good_url_parts_RegExp = /^$/;
var good_url_parts_flag = 0 > 0 ? true : false;  // test for non-zero number of rules
    
// 2629 rules as an efficient NFA RegExp:
var bad_url_parts_RegExp = /(?:\/adcontent\.|\/adsys\/|\/adserver\.|\/pp\-ad\.|\.com\/ads\?|\?getad=&|\/img\/adv\.|\/img\/adv\/|\/expandable_ad\?|\.online\/ads\/|\/online\/ads\/|\/online\-ad_|_online_ad\.|\/ad\-engine\.|\/ad_engine\?|\/homepage\-ads\/|\/homepage\/ads\/|\-web\-ad\-|\/web\-ad_|\-online\-advert\.|\/imgad\.|\/imgad\?|\-leaderboard\-ad\-|\/leaderboard_ad\.|\/leaderboard_ad\/|\/iframead\.|\/iframead\/|\/contentad\/|\/contentad$|\-ad\-content\/|\/ad\/content\/|\/ad_content\.|\/adcontent\/|\/static\/tracking\/|\/ad\-images\/|\/ad\/images\/|\/ad_images\/|\/ad\-image\.|\/ad\/image\/|\/ad_image\.|\/webad\?|_webad\.|\/adplugin\.|\/adplugin\/|\/adplugin_|\-content\-ad\-|\-content\-ad\.|\/content\/ad\/|\/content\/ad_|\/content_ad\.|_content_ad\.|\-iframe\-ad\.|\/iframe\-ad\.|\/iframe\-ad\/|\/iframe\-ad\?|\/iframe\.ad\/|\/iframe\/ad\/|\/iframe\/ad_|\/iframe_ad\.|\/iframe_ad\?|\/video\-ad\.|\/video\/ad\/|\/video_ad\.|\.com\/video\-ad\-|\-ad_leaderboard\/|\/ad\-leaderboard\.|\/ad\/leaderboard\.|\/ad_leaderboard\.|\/ad_leaderboard\/|=ad\-leaderboard\-|\/superads_|_js\/ads\.js|\/web\-analytics\.|\/web_analytics\/|\/_img\/ad_|\/img\/_ad\.|\/img\/ad\-|\/img\/ad\.|\/img\/ad\/|\/img_ad\/|=adcenter&|\/assets\/js\/ad\.|\.adriver\.|\/adriver\.|\/adriver_|\/popad$|\.com\/\?adv=|\/t\/event\.js\?|\-ad\-iframe\.|\-ad\-iframe\/|\-ad\/iframe\/|\/ad\-iframe\-|\/ad\-iframe\.|\/ad\-iframe\?|\/ad\/iframe\.|\/ad\/iframe\/|\/ad\?iframe_|\/ad_iframe\.|\/ad_iframe_|=ad_iframe&|=ad_iframe_|\/pop2\.js$|\/xtclicks\.|\/xtclicks_|\/bottom\-ads\.|\/ad\.php$|\-text\-ads\.|_search\/ads\.js|\/expandable_ad\.php|\/post\/ads\/|\/bg\/ads\/|\-top\-ads\.|\/top\-ads\.|\-show\-ads\.|\/show\-ads\.|\.net\/ad\/|\/ad132m\/|\/footer\-ads\/|\/inc\/ads\/|\/adclick\.|\-iframe\-ads\/|\/iframe\-ads\/|\/iframe\/ads\/|\-ads\-iframe\.|\/ads\/iframe|\/ads_iframe\.|\.co\/ads\/|\/ad_pop\.php\?|\/mobile\-ads\/|\/afs\/ads\/|\/special\-ads\/|\-article\-ads\-|\-video\-ads\/|\/video\-ads\/|\/video\.ads\.|\/video\/ads\/|\/dynamic\/ads\/|\/ad\?count=|\/ad_count\.|\/modules\/ads\/|\.no\/ads\/|\/user\/ads\?|\/i\/ads\/|\/mini\-ads\/|\/js\/ads\-|\/js\/ads\.|\/js\/ads_|\/pc\/ads\.|\/vast\/ads\-|\/cms\/ads\/|\/ad\/logo\/|\/ads\.cms|\/remove\-ads\.|\/player\/ads\.|\/player\/ads\/|\/ads\/html\/|\/td\-ads\-|\/showads\/|\/external\/ads\/|_track\/ad\/|\/ext\/ads\/|\/left\-ads\.|\/default\/ads\/|\/house\-ads\/|\/delivery\.ads\.|\/responsive\-ads\.|\/ads\/click\?|\/media\/ad\/|\/custom\/ads|\/ad\?sponsor=|\/ads12\.|\/sidebar\-ads\/|\-adskin\.|\/adskin\/|\/ads\/targeting\.|\/adsetup\.|\/adsetup_|\/adsframe\.|\/ads_reporting\/|\/ads\/async\/|\/click\?adv=|\/adsdaq_|\/blogad\.|\/popupads\.|&program=revshare&|\/adbanners\/|\/image\/ads\/|\/image\/ads_|\/ads\.htm|\.ads\.css|\/ads\.css|\/click\.track\?|\/banner\-adv\-|\/banner\/adv\/|\/banner\/adv_|\/analytics\.gif\?|\/adlog\.|\/realmedia\/ads\/|\/adsrv\.|\/adsrv\/|\-peel\-ads\-|\/adsys\.|\/log\/ad\-|\/log_ad\?|\/aff_ad\?|\/sponsored_ad\.|\/sponsored_ad\/|\/partner\.ads\.|\/plugins\/ads\-|\/plugins\/ads\/|\/ads\.php|\/ads_php\/|\.link\/ads\/|\/ad_video\.htm|\/lazy\-ads\-|\/lazy\-ads\.|\/ads8\.|\/ads8\/|\/adsjs\.|\/adsjs\/|\/adstop\.|\/adstop_|\/video\-ad\-overlay\.|\.ads1\-|\.ads1\.|\/ads1\.|\/ads1\/|\/ads\/square\-|\/ads\/square\.|&adcount=|\/new\-ads\/|\/new\/ads\/|\/ads\.js\.|\/ads\.js\/|\/ads\.js\?|\/ads\/js\.|\/ads\/js\/|\/ads\/js_|\-adbanner\.|\.adbanner\.|\/adbanner\.|\/adbanner\/|\/adbanner_|=adbanner_|\/adpartner\.|\?adpartner=|\/google_tag\.|\/google_tag\/|\/adClick\/|\/adClick\?|\/s_ad\.aspx\?|\/blog\/ads\/|\-adsonar\.|\/adsonar\.|\/ads\/text\/|\/ads_text_|\/flash\-ads\.|\/flash\-ads\/|\/flash\/ads\/|=popunders&|\/home\/ads\-|\/home\/ads\/|\/home\/ads_|\.ads9\.|\/ads9\.|\/ads9\/|\.adserve\.|\/adserve\-|\/adserve\.|\/adserve\/|\/adserve_|&popunder=|\/popunder\.|\/popunder_|=popunder&|_popunder\+|\-adsystem\-|\/adsystem\.|\/adsystem\/|\/bannerad\.|\/bannerad\/|_bannerad\.|\/ad\.html\?|\/ad\/html\/|\/ad_html\/|\/ads\-new\.|\/ads_new\.|\/ads_new\/|\/ad\/js\/pushdown\.|\-banner\-ads\-|\-banner\-ads\/|\/banner\-ads\-|\/banner\-ads\/|&adspace=|\-adspace\.|\-adspace_|\.adspace\.|\/adspace\.|\/adspace\/|\/adspace\?|\/ads\-top\.|\/ads\/top\-|\/ads\/top\.|\/ads_top_|\.ads3\-|\/ads3\.|\/ads3\/|\/bin\/stats\?|\.adsense\.|\/adsense\-|\/adsense\/|\/adsense\?|;adsense_|\/ads\/index\-|\/ads\/index\.|\/ads\/index\/|\/ads\/index_|\/a\-ads\.|\/web\-ads\.|\/web\-ads\/|\/web\/ads\/|=web&ads=|\-img\/ads\/|\/img\-ads\.|\/img\-ads\/|\/img\.ads\.|\/img\/ads\/|\/site\-ads\/|\/site\/ads\/|\/site\/ads\?|\/adstat\.|\-dfp\-ads\/|\/dfp\-ads\.|\/dfp\-ads\/|\.ads2\-|\/ads2\.|\/ads2\/|\/ads2_|\-adscript\.|\/adscript\.|\/adscript\?|\/adscript_|\.com\/counter\?|_mobile\/js\/ad\.|\-search\-ads\.|\/search\-ads\?|\/search\/ads\?|\/search\/ads_|\/adb_script\/|\/admanager\/|\/images\.ads\.|\/images\/ads\-|\/images\/ads\.|\/images\/ads\/|\/images\/ads_|_images\/ads\/|\/google\/adv\.|&adserver=|\-adserver\-|\-adserver\.|\-adserver\/|\.adserver\.|\/adserver\-|\/adserver\/|\/adserver\?|\/adserver_|\/assets\/sponsored\/|\/adshow\-|\/adshow\.|\/adshow\/|\/adshow\?|\/adshow_|=adshow&|\/media\/ads\/|_media\/ads\/|\/ajax\/track\.php\?|\/plugins\/ad\.|\/static\/ads\/|_static\/ads\/|\-ad\-banner\-|\-ad\-banner\.|\-ad_banner\-|\/ad\-banner\-|\/ad\-banner\.|\/ad\/banner\.|\/ad\/banner\/|\/ad\/banner\?|\/ad\/banner_|\/ad_banner\.|\/ad_banner\/|\/ad_banner_|\-banner\-ad\-|\-banner\-ad\.|\-banner\-ad\/|\/banner\-ad\-|\/banner\-ad\.|\/banner\-ad\/|\/banner\-ad_|\/banner\/ad\.|\/banner\/ad\/|\/banner\/ad_|\/banner_ad\.|_banner\-ad\.|_banner_ad\-|_banner_ad\.|_banner_ad\/|\-google\-ads\-|\-google\-ads\/|\/google\-ads\.|\/google\-ads\/|\/product\-ad\/|\/pages\/ads|\/adpreview\?|\/videoad\.|_videoad\.|\/advlink\.|\.com\/js\/ads\/|\/tracker\/tracker\.js|\/googlead\-|\/googlead\.|_googlead\.|\/js\/_analytics\/|\/js\/analytics\.|\?AdUrl=|\/goad$|\/my\-ad\-injector\/|\/ads\/popshow\.|&advertiserid=|\-images\/ad\-|\/images\-ad\/|\/images\/ad\-|\/images\/ad\/|\/images_ad\/|_images\/ad\.|_images\/ad_|\/adworks\/|\/userad\/|_mainad\.|\/admax\/|_WebAd[^\w.%-]|=advertiser\.|=advertiser\/|\?advertiser=|\.com\/stats\.ashx\?|\.net\/adx\.php\?|\-ad0\.|\/video\-ads\-management\.|\/adblocker\/pixel\.|\.com\/ads\-|\.com\/ads\.|\.com\/ads_|\/com\/ads\/|\/ad\-minister\-|\/ga_social_tracking_|\/video\-ads\-player\.|_ad\.png\?|\/public\/js\/ad\/|\/adwords\/|\/embed\-log\.js|\/ad\-manager\/|\/ad_manager\.|\/ad_manager\/|\/adfactory\-|\/adfactory_|\/adplayer\-|\/adplayer\/|\.com\/im\-ad\/|\.com\/im_ad\/|\-adops\.|\/adops\/|\/adimg\/|\/js\/oas\-|\/js\/oas\.|=adlabs&|\.com\/\?ad=|\.com\/ad\?|\/adlink\?|\/adlink_|\/ajax\-track\-view\.|\/adsterra\/|\/images\/adver\-|\-advertising\/assets\/|\/adseo\/|\-google\-ad\.|\/google\-ad\-|\/google\-ad\?|\/google\/ad\?|\/google_ad\.|_google_ad\.|\/ads\/ads\.|\/ads\/ads\/|\/ads\/ads_|\-advt\.|\/advt\/|\/ad\.css\?|\/\?advideo\/|\?advideo_|\/tracking\/track\.php\?|\-ad\-pixel\-|\/\?addyn$|\/analytics\-v1\.|\/admedia\/|\/socialads\/|_smartads_|\/tracker\/track\.php\?|\/images\/ad2\/|\/track\/track\.php\?|\.ads4\-|\/ads4\/|\-adman\/|\/adman\/|\/adman_|\/campaign\/advertiser_|\/utep_ad\.js|\/flashads\/|\/wp\-content\/ads\/|\/adbroker\.|\/adbroker\/|\/pop_ad\.|_pop_ad\.|_pop_ad\/|\-adtrack\.|\/adtrack\/|\/amp\-ad\-|\/_\/ads\/|\/advertisments\/|\-image\-ad\.|\/image\/ad\/|\/adnow\-|\/g_track\.php\?|\.net\/ads\-|\.net\/ads\.|\.net\/ads\/|\.net\/ads\?|\.net\/ads_|\/adblock\-img\.|\/sensorsdata\-|&adurl=|\/img\-advert\-|\?adx=|\/chartbeat\.js|_chartbeat\.js|\/adblock_alerter\.|\/adblock\-alerter\/|\/admaster\?|\/ero\-advertising\.|\/ajax\/optimizely\-|\/adx\/iframe\.|\/adx_iframe_|\/adservice\-|\/adservice\/|\/adservice$|\/adv\-expand\/|\.core\.tracking\-min\-|\/show\-ad\.|\/show\.ad\?|\/show_ad\.|\/show_ad\?|\/intelliad\.|\/leaderboard\-advert\.|\?affiliate=|&adnet=|\/adiframe\.|\/adiframe\/|\/adiframe\?|\/adiframe_|\/getad\/|\/getad\?|\/adrolays\.|\/pixel\/js\/|\/adhandler\.|\/adimages\.|\/exoclick$|\/nuggad\.|\/nuggad\/|\.net\/ad2\/|\/adguru\.|\-adspot\-|\/adspot\/|\/adspot_|\?adspot_|\/analytics\/track\-|\/analytics\/track\.|\/analytics\/track\/|\/analytics\/track\?|\/analytics\/track$|\/ad_pop\.|\/googleads\-|\/googleads\/|\/googleads_|_googleads_|_doubleclick\.|\/adcash\-|\/adcash$|\/iframes\/ad\/|\/adverthorisontalfullwidth\.|\.AdmPixelsCacheController\?|\/adaptvexchangevastvideo\.|\/ForumViewTopicContentAD\.|\/postprofilehorizontalad\.|=adreplacementWrapperReg\.|\/adClosefeedbackUpgrade\.|\/adzonecenteradhomepage\.|\/ForumViewTopicBottomAD\.|\/advertisementrotation\.|\/advertisingimageexte\/|\/AdvertisingIsPresent6\?|\/postprofileverticalad\.|\/adblockdetectorwithga\.|\/admanagementadvanced\.|\/advertisementmapping\.|\/initlayeredwelcomead\-|\/advertisementheader\.|\/advertisingcontent\/|\/advertisingwidgets\/|\/thirdpartyframedad\/|\.AdvertismentBottom\.|\/adfrequencycapping\.|\/adgearsegmentation\.|\/advertisementview\/|\/advertising300x250\.|\/advertverticallong\.|\/AdZonePlayerRight2\.|\/ShowInterstitialAd\.|\/adwizard\.|\/adwizard\/|\/adwizard_|\/addeliverymodule\/|\/adinsertionplugin\.|\/AdPostInjectAsync\.|\/adrendererfactory\.|\/advertguruonline1\.|\/advertisementAPI\/|\/advertisingbutton\.|\/advertisingmanual\.|\/advertisingmodule\.|\/adzonebelowplayer\.|\/adzoneplayerright\.|\/jumpstartunpaidad\.|\?adtechplacementid=|\/adasiatagmanager\.|\/adforgame160x600\.|\/adframe728homebh\.|\/adleaderboardtop\.|\/adpositionsizein\-|\/adreplace160x600\.|\/advertise125x125\.|\/advertisement160\.|\/advertiserwidget\.|\/advertisinglinks_|\/advFrameCollapse\.|\/requestmyspacead\.|\/supernorthroomad\.|\/adblockdetection\.|\/adBlockDetector\/|\/cpx\-advert\/|\.advertrecycling\.|\/adbriteincleft2\.|\/adbriteincright\.|\/adchoicesfooter\.|\/adgalleryheader\.|\/adindicatortext\.|\/admatcherclient\.|\/adoverlayplugin\.|\/adreplace728x90\.|\/adtaggingsubsec\.|\/adtagtranslator\.|\/adultadworldpop_|\/advertisements2\.|\/advertisewithus_|\/adWiseShopPlus1\.|\/adwrapperiframe\.|\/contentmobilead\.|\/convertjsontoad\.|\/HompageStickyAd\.|\/mobilephonesad\/|\/sample300x250ad\.|\/tomorrowfocusAd\.|\/adforgame728x90\.|\/adforgame728x90_|\/AdblockMessage\.|\/AdAppSettings\/|\/adinteraction\/|\/adaptvadplayer\.|\/adcalloverride\.|\/adfeedtestview\.|\/adframe120x240\.|\/adframewrapper\.|\/adiframeanchor\.|\/adlantisloader\.|\/adlargefooter2\.|\/adpanelcontent\.|\/adverfisement2\.|\/advertisement1\.|\/advertisement2\.|\/advertisement3\.|\/dynamicvideoad\?|\/premierebtnad\/|\/rotatingtextad\.|\/sample728x90ad\.|\/slideshowintad\?|\/adblockchecker\.|\/adblockdetect\.|\/adblockdetect\/|\-advertising11\.|\/adchoicesicon\.|\/adframe728bot\.|\/adframebottom\.|\/adframecommon\.|\/adframemiddle\.|\/adinsertjuicy\.|\/adlargefooter\.|\/adleftsidebar\.|\/admanagement\/|\/adMarketplace\.|\/admentorserve\.|\/adotubeplugin\.|\/adPlaceholder\.|\/advaluewriter\.|\/adverfisement\.|\/advertbuttons_|\/advertising02\.|\/advertisment1\-|\/advertisment4\.|\/bottomsidead\/|\/getdigitalad\/|\/gigyatargetad\.|\/gutterspacead\.|\/leaderboardad\.|\/newrightcolad\.|\/promobuttonad\.|\/rawtubelivead\.|\/restorationad\-|=admodeliframe&|\/adblockkiller\.|\/addpageview\/|\/admonitoring\.|&customSizeAd=|\-printhousead\-|\.advertmarket\.|\/AdBackground\.|\/adcampaigns\/|\/adcomponent\/|\/adcontroller\.|\/adfootcenter\.|\/adframe728b2\.|\/adifyoverlay\.|\/admeldscript\.|\/admentor302\/|\/admentorasp\/|\/adnetwork300\.|\/adnetwork468\.|\/AdNewsclip14\.|\/AdNewsclip15\.|\/adoptionicon\.|\/adrequisitor\-|\/adTagRequest\.|\/adtechHeader\.|\/adtechscript\.|\/adTemplates\/|\/advertisings\.|\/advertsquare\.|\/advertwebapp\.|\/advolatility\.|\/adzonebottom\.|\/adzonelegend\.|\/brightcovead\.|\/contextualad\.|\/custom11x5ad\.|\/horizontalAd\.|\/iframedartad\.|\/indexwaterad\.|\/jsVideoPopAd\.|\/PageBottomAD\.|\/skyscraperad\.|\/writelayerad\.|=dynamicwebad&|\-advertising2\-|\/advertising2\.|\/advtemplate\/|\/advtemplate_|\/adimppixel\/|\-adcompanion\.|\-adtechfront\.|\-advertise01\.|\-rightrailad\-|\.xinhuanetAD\.|\/728x80topad\.|\/adchoices16\.|\/adchoicesv4\.|\/adcollector\.|\/adcontainer\?|\/addelivery\/|\/adfeedback\/|\/adfootright\.|\/AdformVideo_|\/adfoxLoader_|\/adframe728a\.|\/adframe728b\.|\/adfunctions\.|\/adgenerator\.|\/adgraphics\/|\/adhandlers2\.|\/adheadertxt\.|\/adhomepage2\.|\/adiframetop\.|\/admanagers\/|\/admetamatch\?|\/adpictures\/|\/adpolestar\/|\/adPositions\.|\/adproducts\/|\/adrequestvo\.|\/adrollpixel\.|\/adtopcenter\.|\/adtopmidsky\.|\/advcontents\.|\/advertises\/|\/advertlayer\.|\/advertright\.|\/advscripts\/|\/adzoneright\.|\/asyncadload\.|\/crossoverad\-|\/dynamiccsad\?|\/gexternalad\.|\/indexrealad\.|\/instreamad\/|\/internetad\/|\/lifeshowad\/|\/newtopmsgad\.|\/o2contentad\.|\/propellerad\.|\/showflashad\.|\/SpotlightAd\-|\/targetingAd\.|_companionad\.|\.adplacement=|\/adplacement\.|\/adversting\/|\/adversting\?|\-NewStockAd\-|\.adgearpubs\.|\.rolloverad\.|\/300by250ad\.|\/adbetween\/|\/adbotright\.|\/adboxtable\-|\/adbriteinc\.|\/adchoices2\.|\/adcontents_|\/AdElement\/|\/adexclude\/|\/adexternal\.|\/adfillers\/|\/adflashes\/|\/adFooterBG\.|\/adfootleft\.|\/adformats\/|\/adframe120\.|\/adframe468\.|\/adframetop\.|\/adhandlers\-|\/adhomepage\.|\/adiframe18\.|\/adiframem1\.|\/adiframem2\.|\/adInfoInc\/|\/adlanding\/|\/admanager3\.|\/admanproxy\.|\/admcoreext\.|\/adorika300\.|\/adorika728\.|\/adperfdemo\.|\/AdPreview\/|\/adprovider\.|\/adreplace\/|\/adrequests\.|\/adrevenue\/|\/adrightcol\.|\/adrotator2\.|\/adtextmpu2\.|\/adtopright\.|\/adv180x150\.|\/advertical\.|\/advertmsig\.|\/advertphp\/|\/advertpro\/|\/advertrail\.|\/advertstub\.|\/adviframe\/|\/advlink300\.|\/advrotator\.|\/advtarget\/|\/AdvWindow\/|\/adwidgets\/|\/adWorking\/|\/adwrapper\/|\/adxrotate\/|\/AdZoneAdXp\.|\/adzoneleft\.|\/baselinead\.|\/deliverad\/|\/DynamicAd\/|\/getvideoad\.|\/lifelockad\.|\/lightboxad[^\w.%-]|\/neudesicad\.|\/onplayerad\.|\/photo728ad\.|\/postprocad\.|\/pushdownAd\.|\/PVButtonAd\.|\/renewalad\/|\/rotationad\.|\/sidelinead\.|\/slidetopad\.|\/tripplead\/|\?adlocation=|\?adunitname=|_preorderad\.|\-adrotation\.|\/adgallery2\.|\/adgallery2$|\/adgallery3\.|\/adgallery3$|\/adinjector\.|\/adinjector_|\/adpicture1\.|\/adpicture1$|\/adpicture2\.|\/adpicture2$|\/adrotation\.|\/externalad\.|_externalad\.|\-adfliction\.|\-adfliction\/|\/adfliction\-|\/adfox\/|\?adfox_|\/adbDetect\.|\/adbDetect\/|\/adcontrol\.|\/adcontrol\/|\/adinclude\.|\/adinclude\/|\/adkingpro\-|\/adkingpro\/|\/adoverlay\.|\/adoverlay\/|&adgroupid=|&adpageurl=|\-Ad300x250\.|\-ContentAd\-|\/125x125ad\.|\/300x250ad\.|\/ad125x125\.|\/ad160x600\.|\/ad1x1home\.|\/ad2border\.|\/ad2gather\.|\/ad300home\.|\/ad300x145\.|\/ad600x250\.|\/ad600x330\.|\/ad728home\.|\/adactions\.|\/adasset4\/|\/adbayimg\/|\/adblock26\.|\/adbotleft\.|\/adcentral\.|\/adchannel_|\/adclutter\.|\/adengage0\.|\/adengage1\.|\/adengage2\.|\/adengage3\.|\/adengage4\.|\/adengage5\.|\/adengage6\.|\/adexample\?|\/adfetcher\?|\/adfolder\/|\/adforums\/|\/adheading_|\/adiframe1\.|\/adiframe2\.|\/adiframe7\.|\/adiframe9\.|\/adinator\/|\/AdLanding\.|\/adLink728\.|\/adlock300\.|\/admarket\/|\/admeasure\.|\/admentor\/|\/adNdsoft\/|\/adonly468\.|\/adopspush\-|\/adoptions\.|\/adreclaim\-|\/adrelated\.|\/adruptive\.|\/adtopleft\.|\/adunittop$|\/advengine\.|\/advertize_|\/advertsky\.|\/advertss\/|\/adverttop\.|\/advfiles\/|\/adviewas3\.|\/advloader\.|\/advscript\.|\/advzones\/|\/adwriter2\.|\/adyard300\.|\/adzonetop\.|\/AtomikAd\/|\/contentAd\.|\/contextad\.|\/delayedad\.|\/devicead\/|\/dynamicad\?|\/fetchJsAd\.|\/galleryad\.|\/getTextAD\.|\/GetVASTAd\?|\/invideoad\.|\/MonsterAd\-|\/PageTopAD\.|\/pitattoad\.|\/prerollad\.|\/processad\.|\/ProductAd\.|\/proxxorad\.|\/showJsAd\/|\/siframead\.|\/slideinad\.|\/sliderAd\/|\/spiderad\/|\/testingad\.|\/tmobilead\.|\/unibluead\.|\/vert728ad\.|\/vplayerad\.|\/VXLayerAd\-|\/welcomead\.|=DisplayAd&|\?adcentric=|\?adcontext=|\?adflashid=|\?adversion=|\?advsystem=|\/admonitor\-|\/admonitor\.|\/adrefresh\-|\/adrefresh\.|\/defaultad\.|\/defaultad\?|\/adconfig\.|\/adconfig\/|\/addefend\.|\/addefend\/|\/adfactor\/|\/adfactor_|\/adframes\.|\/adframes\/|\/adloader\.|\/adloader\/|\/adwidget\/|\/adwidget_|\/bottomad\.|\/bottomad\/|\/buttonad\/|_buttonad\.|&adclient=|\/adclient\-|\/adclient\.|\/adclient\/|\-Ad300x90\-|\-adcentre\.|\/768x90ad\.|\/ad120x60\.|\/ad1place\.|\/ad290x60_|\/ad468x60\.|\/ad468x80\.|\/AD728cat\.|\/ad728rod\.|\/adarena\/|\/adasset\/|\/adblockl\.|\/adblockr\.|\/adborder\.|\/adbot160\.|\/adbot300\.|\/adbot728\.|\/adbottom\.|\/AdBoxDiv\.|\/adboxes\/|\/adbrite2\.|\/adbucket\.|\/adbucks\/|\/adcast01_|\/adcframe\.|\/adcircle\.|\/adcodes\/|\/adcommon\?|\/adcxtnew_|\/addeals\/|\/adError\/|\/adfooter\.|\/adframe2\.|\/adfront\/|\/adgetter\.|\/adheader\.|\/adhints\/|\/adifyids\.|\/adindex\/|\/adinsert\.|\/aditems\/|\/adlantis\.|\/adleader\.|\/adlinks2\.|\/admicro2\.|\/adModule\.|\/adnotice\.|\/adonline\.|\/adpanel\/|\/adparts\/|\/adplace\/|\/adplace5_|\/adremote\.|\/adroller\.|\/adtagcms\.|\/adtaobao\.|\/adtimage\.|\/adtonomy\.|\/adtop160\.|\/adtop300\.|\/adtop728\.|\/adtopsky\.|\/adtvideo\.|\/advelvet\-|\/advert01\.|\/advert24\.|\/advert31\.|\/advert32\.|\/advert33\.|\/advert34\.|\/advert35\.|\/advert36\.|\/advert37\.|\/adverweb\.|\/adviewed\.|\/adviewer\.|\/adzilla\/|\/anchorad\.|\/attachad\.|\/bigboxad\.|\/btstryad\.|\/couponAd\.|\/customad\.|\/getmyad\/|\/gutterAd\.|\/incmpuad\.|\/injectad\.|\/insertAd\.|\/insideAD\.|\/jamnboad\.|\/jstextad\.|\/leaderad\.|\/localAd\/|\/masterad\.|\/mstextad\?|\/multiad\/|\/noticead\.|\/notifyad\.|\/pencilad\.|\/pledgead\.|\/proto2ad\.|\/salesad\/|\/scrollAd\-|\/spacead\/|\/squaread\.|\/stickyad\.|\/stocksad\.|\/topperad\.|\/tribalad\.|\/VideoAd\/|\/widgetad\.|=ad320x50\-|=adexpert&|\?adformat=|\?adPageCd=|\?adTagUrl=|_adaptvad\.|_StickyAd\.|\-adhelper\.|\/468x60ad\.|\/adhelper\.|\/admarker\.|\/admarker_|\/commonAD\.|\/footerad\.|\/footerad\?|\/headerad\.|_468x60ad\.|_commonAD\.|_headerad\.|\-admarvel\/|\.admarvel\.|\/admarvel\.|\/adometry\-|\/adometry\.|\/adometry\?|\-web\-advert\-|_web\-advert\.|\/adblockDetector\.|\/adcycle\.|\/adcycle\/|\/adfiles\.|\/adfiles\/|\/adpeeps\.|\/adpeeps\/|\/adproxy\.|\/adproxy\/|\/advalue\/|\/advalue_|\/adzones\.|\/adzones\/|\/printad\.|\/printad\/|\/servead\.|\/servead\/|\-adimage\-|\/adimage\.|\/adimage\/|\/adimage\?|\/adpixel\.|&largead=|\-adblack\-|\-adhere2\.|\/ad160px\.|\/ad2gate\.|\/ad2push\.|\/ad300f2\.|\/ad300ws\.|\/ad728f2\.|\/ad728ws\.|\/AdAgent_|\/adanim\/|\/adasync\.|\/adboxbk\.|\/adbridg\.|\/adbytes\.|\/adcache\.|\/adctrl\/|\/adedge\/|\/adentry\.|\/adfeeds\.|\/adfever_|\/adflash\.|\/adfshow\?|\/adfuncs\.|\/adgear1\-|\/adgear2\-|\/adhtml\/|\/adlandr\.|\/ADMark\/|\/admatch\-|\/admatik\.|\/adnexus\-|\/adning\/|\/adpagem\.|\/adpatch\.|\/adplan4\.|\/adpoint\.|\/adpool\/|\/adpop32\.|\/adprove_|\/adpush\/|\/adratio\.|\/adroot\/|\/adrotat\.|\/adrotv2\.|\/adtable_|\/adtadd1\.|\/adtagtc\.|\/adtext2\.|\/adtext4\.|\/adtomo\/|\/adtraff\.|\/adutils\.|\/advault\.|\/advdoc\/|\/advert4\.|\/advert5\.|\/advert6\.|\/advert8\.|\/adverth\.|\/advinfo\.|\/adVisit\.|\/advris\/|\/advshow\.|\/adweb33\.|\/adwise\/|\/adzbotm\.|\/adzerk2_|\/adzone1\.|\/adzone4\.|\/bookad\/|\/coread\/|\/flashad\.|\/flytead\.|\/gamead\/|\/hoverad\.|\/imgaad\/|\/jsonad\/|\/LayerAd[^\w.%-]|\/modalad\.|\/nextad\/|\/panelad\.|\/photoad\.|\/promoAd\.|\/rpgetad\.|\/safead\/|\/ServeAd\?|\/smartAd\?|\/transad\.|\/trendad\.|\?adclass=|&advtile=|&smallad=|\-advert3\.|\-sync2ad\-|\.adforge\.|\.admicro\.|\/adcheck\.|\/adcheck\?|\/adfetch\.|\/adfetch\?|\/adforge\.|\/adlift4\.|\/adlift4_|\/adlinks\.|\/adlinks_|\/admicro_|\/adttext\-|\/adttext\.|\/advert3\.|\/smallad\-|\/sync2ad\.|\?advtile=|\-adchain\.|\-advert2\.|\/adchain\-|\/adchain\.|\/advert2\-|\/advert2\.|\/layerad\-|\/layerad\.|_layerad\.|\/adfile\.|\/adfile\/|\/adleft\.|\/adleft\/|\/peelad\.|\/peelad\/|\/sidead\.|\/sidead\/|\/viewad\.|\/viewad\/|\/viewad\?|_sidead\.|&adzone=|\/adzone\.|\/adzone\/|\/adzone_|\?adzone=|\/adinfo\?|\/adpv2\/|\/adtctr\.|\/adtrk\/|&adname=|&AdType=|\.adnwif\.|\.adpIds=|\/ad000\/|\/ad125b\.|\/ad136\/|\/ad160k\.|\/ad2010\.|\/ad2con\.|\/ad300f\.|\/ad300s\.|\/ad300x\.|\/ad728f\.|\/ad728s\.|\/ad728t\.|\/ad728w\.|\/ad728x\.|\/adbar2_|\/adbase\.|\/adbebi_|\/adbl1\/|\/adbl2\/|\/adbl3\/|\/adblob\.|\/adbox1\.|\/adbox2\.|\/adcast_|\/adcla\/|\/adcomp\.|\/adcss\/|\/add728\.|\/adfeed\.|\/adfly\/|\/adicon_|\/adinit\.|\/adjoin\.|\/adjsmp\.|\/adjson\.|\/adkeys\.|\/adlens\-|\/admage\.|\/admega\.|\/adnap\/|\/ADNet\/|\/adnet2\.|\/adnew2\.|\/adpan\/|\/adperf_|\/adping\.|\/adpix\/|\/adplay\.|\/AdPub\/|\/adRoll\.|\/adtabs\.|\/adtago\.|\/adunix\.|\/adutil\.|\/Adv150\.|\/Adv468\.|\/advobj\.|\/advPop\.|\/advts\/|\/advweb\.|\/adweb2\.|\/adx160\.|\/adyard\.|\/adztop\.|\/ajaxAd\?|\/baseAd\.|\/bnrad\/|\/boomad\.|\/cashad\.|\/cubead\.|\/curlad\.|\/cutead\.|\/DemoAd\.|\/dfpad\/|\/divad\/|\/drawad\.|\/ebayad\.|\/flatad\.|\/freead\.|\/fullad\.|\/geoad\/|\/GujAd\/|\/idleAd\.|\/ipadad\.|\/livead\-|\/metaad\.|\/MPUAd\/|\/navad\/|\/newAd\/|\/Nuggad\?|\/postad\.|\/railad\.|\/retrad\.|\/rollad\.|\/rotad\/|\/svnad\/|\/tinyad\.|\/toonad\.|=adMenu&|\?adarea=|\?advurl=|&adflag=|&adlist=|\.adwolf\.|\/adback\.|\/adback\?|\/adflag\.|\/adlist_|\/admain\.|\/admain$|\/adwolf\.|\/adworx\.|\/adworx_|\/footad\-|\/footad\.|\/skinad\.|_skinad\.|\.lazyad\-|\/lazyad\-|\/lazyad\.|\/adverserve\.|\/google\-analytics\-|\/google\-analytics\.|\/google\/analytics_|\/google_analytics\.|\/adpic\.|\/adpic\/|\/adwiz\.|\/adwiz\/|\/flyad\.|\/flyad\/|\.biz\/ad2\/|\/get\-advert\-|\/adimp\?|\/adpv\/|&adnum=|\-NewAd\.|\-webAd\-|\/120ad\.|\/300ad\.|\/468ad\.|\/ad11c\.|\/ad125\.|\/ad160\.|\/ad234\.|\/ad250\.|\/ad336\.|\/ad350\.|\/ad468\.|\/adban\.|\/adbet\-|\/adbot_|\/adbtr\.|\/adbug_|\/adCfg\.|\/adcgi\?|\/adfrm\.|\/adGet\.|\/adGpt\.|\/adhug_|\/adixs\.|\/admgr\.|\/adnex\.|\/adpai\.|\/adPos\?|\/adrun\.|\/advdl\.|\/advf1\.|\/advhd\.|\/advph\.|\/advt2\.|\/adxcm_|\/adyea\.|\/affad\?|\/bizad\.|\/buyad\.|\/ciaad\.|\/cnxad\-|\/getAd;|\/ggad\/|\/KfAd\/|\/kitad\.|\/layad\.|\/ledad\.|\/mktad\.|\/mpuad\.|\/natad\.|\/picAd\.|\/pubad\.|\/subAd\.|\/txtad\.|\/ypad\/|\?adloc=|\?PopAd=|_125ad\.|_250ad\.|_FLYAD\.|\.homad\.|\.intad\.|\.intad\/|\/ad728\-|\/ad728\.|\/adrot\.|\/adrot_|\/newad\.|\/newad\?|_homad\.|\/adrum\-|\/adrum\.|\/adrum_|\/ad2\/index\.|\/widget\-advert\.|\/widget\-advert\?|\/admp\-|\-ad03\.|\.adru\.|\/ad12\.|\/ad15\.|\/ad1r\.|\/ad3i\.|\/ad41_|\/ad4i\.|\/adbn\?|\/adfr\.|\/adjk\.|\/adnl\.|\/adv1\.|\/adv2\.|\/adv5\.|\/adv6\.|\/adv8\.|\/adw1\.|\/adw2\.|\/adw3\.|\/adx2\.|\/adxv\.|\/bbad\.|\/cyad\.|\/o2ad\.|\/pgad\.|\.win\/ads\/|\/adition\.|\/admeta\.|=admeta&|\-advertising\/vast\/|\/ad8\.|\/gujAd\.|\/ajax\-advert\-|\/ajax\-advert\.|\/ad_campaigns\/|\/telegraph\-advertising\/|\/jsad\/|\/2\/ads\/|\/1\/ads\/|\/bg\-advert\-|\/Ad\.asmx\/|\/ad2\/res\/|\/adx\-exchange\.|\/ad_contents\/|\/collections\/ads\-|\.com\/ad2\/|\/adtest\.|\/adtest\/|\-js\-advertising\-|\/banner\.asp\?|\/wp_stat\.php\?|\.com\/log\?event|\/img2\/ad\/|\/adgallery1\.|\/adgallery1$|\-analytics\/analytics\.|\/stream\-ad\.|\.nl\/ad2\/|\/bottom\-advert\-|\/content\/adv\/|\.com\/js\/ad\.|\/ad\/swf\/|\/site_under\.|\?ad\.vid=|\-advert\-placeholder\.|\/cn\-advert\.|\/ados\?|\-gif\-advert\.|\.uk\/track\?|\/scripts\/adv\.|\/advs\/|\/adv_script_|\/script\-adv\-|\?advert_key=|\/ad\/img\/|\/ad_img\.|\/ad_img\/|\/clickability\-|\/clickability\/|\/clickability\?|_clickability\/|\/ad2\-728\-|\-article\-advert\-|\/article\-advert\-|\/ad\.aspx\?|_tracker_min\.|\/images\.adv\/|\/images\/adv\-|\/images\/adv\.|\/images\/adv\/|\/images\/adv_|\?adunitid=|\/layer\-advert\-|\/affiliate_link\.js|\-advert\-100x100\.|\/site\-advert\.|\/e\-advertising\/|\.v4\.analytics\.|\/v4\/analytics\.|\/native\-advertising\/|\/google\/analytics\.js|\/scripts\/ad\-|\/scripts\/ad\.|\/scripts\/ad\/|\/scripts\/ad_|\-ad\-scripts\?|\/ad\/script\/|\/ad_script\.|\/ad_script_|\/ad24\/|\/adsatt\.|\?adunit_id=|\/wp\-content\/plugins\/wp\-super\-popup\-pro\/|\-ads\-manager\/|\/ads_manager\.|\/adclix\.|\/wp\-srv\/ad\/|\/show_ads\.js|\.com\/adds\/|\/click\-stat\.js|\/wp\-admin\/admin\-ajax\.php\?action=adblockvisitor|\/eureka\-ads\.|&advid=|\/event\-tracking\.js|\.php\?id=ads_|\/adpicture\.|\-ad1\.|\/ad1_|\/stats\/tracker\.js|\/ad\/afc_|\-page\-ad\.|\-page\-ad\?|\/page\/ad\/|\/global\-analytics\.js|\/statistics\.php\?data=|\/adtype\.|\/adtype=|\?adtype=|\/ga_link_tracker_|\/adv3\.|\/scripts\/stats\/|\.jsp\?adcode=|\/adv_horiz\.|\/ad_entry_|\/ad728x15\.|\/ad728x15_|\/analytics\.v1\.js|\/ads_9_|\/images\/adds\/|\/set\-cookie\.gif\?|\/static\/js\/4728ba74bc\.js|\/wp\-js\/analytics\.|\/ad\-exchange\.|\/stat\-analytics\/|\/chitika\-ad\?|\/statistics\.js\?|\/ads300\.|\-ad\-left\.|\/ad\-left\.|\/ad_left\.|\/ad_left_|\-ad\.jpg\?|\/internal\-ad\-|\/adgeo\/|\/marketing\/js\/analytics\/|\.in\/ads\.|\.in\/ads\/|\/js\/tracker\.js|\/ad\/files\/|\/ad_files\/|\/affiliate_member_banner\/|\/assets\/uts\/|\/files\/ad\-|\/files\/ad\/|_files\/ad\.|\/ads\/zone\/|\/ads\?zone=|\-adsmanager\/|\/adsmanager\/|\/adtag\.|\/adtag\/|\/adtag\?|\/adtag_|\?adtag=|\/post\-ad\-|\/adsx\/|\.ws\/ads\/|\/corner\-ad\.|\.com\/log\?type|\/ad_multi_|\/yandex\-metrica\-watch\/|\/b3\.php\?img=|\/ad_horiz\.|\/exports\/tour\/|\/js\/tracking\.js|\/stats\-tracking\.js|\/adp\-pro\/|\/adv\.php|\.fr\/ads\.|\/popad\-|\/popad\.|\/ad\-hcm\.|\/gravity\-beacon\.js|\/ad\-blocker\.js|_temp\/ad_|\/story_ad\.|\/wp\-content\/uploads\/useful_banner_manager_banners\/|\-adv\-v1\/|\/addyn\/3\.0\/|\-ad\-random\/|\/ad\/random_|\/wp\-content\/plugins\/anti\-block\/|\/reklam\-ads2\.|\/vs\-track\.js|\/tracking_link_cookie\.|\/AdvertAssets\/|\/assets\/adv\/|\.com\/adv\/|\.com\/adv\?|\.com\/adv_|\/widget\/ad\/|_widget_ad\.|\/aff_banner\/|\/webmaster_ads\/|\.hr\/ads\.|\/images\/bg_ad\/|\/Ad\/Oas\?|\/all\/ad\/|\$csp=worker\-src 'none',domain=estream\.to$flashx\.cc$flashx\.co$flashx\.co$streamango\.com$vidoza\.co$vidoza\.net$vidto\.me$vidto\.se$vidtudu\.com|\/ad\.min\.|\/log_stats\.php\?|\/ad\/cross\-|\/ad_campaign\?|\-ads\-placement\.|\/lib\/ad\.js|\/250x250\-adverts\.|\/context_ad\/|\/adx_flash\.|\/adv_image\/|\/image\/adv\/|\/partner\/transparent_pixel\-|\/rcom\-video\-ads\.|\/stat\.php\?|\/publisher\.ad\.|\/ads_openx_|&admeld_|\/admeld\.|\/admeld\/|\/admeld_|=admeld&|\/adz\/images\/|\-advertisement\/script\.|\.net\/affiliate\/|\.xyz\/ads\/|\/Article\-Ad\-|\/adzonesidead\.|\/images\/adz\-|\/images\/adz\/|\/cpx\-ad\.|\/advpreload\.|\/Cookie\?merchant=|\/trackings\/addview\/|\/ad\-third\-party\/|\/adv_top\.|\/rtt\-log\-data\?|\?event=advert_|\/bi_affiliate\.js|\/pub\/js\/ad\.|\/ads\.json\?|\/adclixad\.|\/adreload\.|\/adreload\?|\-your\-ad\-here\-|\/ip\-advertising\/|\/_30\/ads\/|\/create\-lead\.js|\/ad\/generate\?|\/generate_ad\.|\-ads\/oas\/|\/ads\/oas\-|\/ads\/oas\/|\/analytics\-assets\/|\/adifyad\.|\/adblock\.js|\/assets\/analytics\:|\.tv\/adl\.|\/youtube\-track\-event_|\/ad_rotation\.|\/tracker_czn\.tsp\?|\/adload\.|\/active\-ad\-|\/md\.js\?country=|&adsize=|\?adsize=|\/assets\/ad\-|\/assets\/ad\/|\/websie\-ads\-|\/addLinkerEvents\-std\.|\-load\-advert\.|\/impressions\/log\?|\/ad\-builder\.|\/ads\/xtcore\.|\-gallery_ad\/|\/tracking_add_ons\.|\-ads\/video\.|\/ads\/video\/|\/ads\/video_|\/pagead\.|\/pagead\?|\/pickle\-adsystem\/|\/admin\/banners\/|\/affiliate\/ads\/|\/affiliate\-assets\/banner\/|\/ad\/timing\.|\/wp\-content\/plugins\/deadblocker\/|\/affiliates\/contextual\.|\/assets\/tracking\-|\/client\-event\-logger\.|\/nd_affiliate\.|\/ajax\-ad\/|\/ajax\/ad\/|\/affiliate_show_banner\.|\/promo\/ad_|_promo_ad\/|\/pixiedust\-build\.js|\/affiliate\.linker\/|\/affiliate\/small_banner\/|\/affiliate\.1800flowers\.|\/affiliate\/displayWidget\?|\/ad_medium_|\/share\/ads\/|\/ad_mini_|\/ads\/branding\/|\/ad\/display\.php|\/adv\/mjx\.|\/mail_tracking\-cg\.php|\/ad\/ad2\/|\/search\-cookie\.aspx\?|\/adv\/topBanners\.|\-amazon\-ads\/|\/adbrite\-|\/adbrite\.|\/adbrite\/|\/adbrite_|\/tracker\.json\.php\?|\/adv\/bottomBanners\.|\/ads\-rec$|\/ads\/navbar\/|\/ads\-admin\.|\/ade\/baloo\.php|\/idevaffiliate\/banners\/|\/adblock\-relief\/|_ads\-affiliates_|\/affiliate_base\/banners\/|\/adsmm\.dll\/|\/tracked_ad\.|\/im\-ad\/im\-rotator2\.|\/cookie\?affiliate|\-load\-ads\.|\/load\-ads$|\/ads\.load\.|\/ads\/load\.|\/ads_load\/|\/wp\-content\/tracker\.|\/watchonline_cookies\.|\/affiliate_show_iframe\.|\/zalando\-ad\-|\/plugin\/trackEvents\.|\/ads\/contextual\.|\/ads\/contextual_|\/sponsor%20banners\/|\/utm_cookie\.|\.html\?ad=|\.html\?ad_|\/html\/ad\.|\/html\/ad\/|\/tracking\.js\?site_id=|\/websie\-ads3\.|\/libs\/tracker\.js|\-simple\-ads\.|\/CookieManager\-bdl\?|\-ad\-gif\-|\/ad\.gif$|\/ad_gif\/|\/ad_gif_|_ad\.gif$|\/adjs\.|\/adjs\/|\/adjs\?|\/adjs_|\/ad_system\/|\/polopoly_fs\/ad\-|\/ads\/head\.|\/hostkey\-ad\.|\/ad\-catalogue\-|\.ad\-ocad\.|\/ga_no_cookie\.|\/ga_no_cookie_|\-ad\-cube\.|\/ads\-common\.|\/ads\/common\/|\/ad_fixedad\.|\/3rd\-party\-stats\/|\/ad_bannerPool\-|\/bannerfile\/ad_|\.lazyload\-ad\-|\.lazyload\-ad\.|\/ad_lazyload\.|\/ad\/superbanner\.|\/econa\-site\-search\-ajax\-log\-referrer\.php|\/no\-adblock\/|\/ifolder\-ads\.|\/comscore_beacon\.|\/ads\/menu_|\/skype\-analytics\.|\-theme\/ads\/|_theme\/ads\/|\/adv\.png|\/p2\/ads\/|\/watch\?shu=|\/ad_selectMainfixedad\.|\-ads\/static\-|\/akamai_analytics_|\/sitetestclickcount\.enginedocument,script,subdocument|\/ads\/creatives\/|\/flashtag\.txt\?Log=|\/init_cookie\.php\?|\/adv_flash\.|\/ads\?cookie_|\/comscore_engine\.|\/json\/ad\/|\/adonis_event\/|\/pagead\/ads\?|\/analytics\/urlTracker\.|\?event=performancelogger\:|\/ads_ifr\.|\/tracker\/eventBatch\/|\.ad\.json\?|_stat\/addEvent\/|\/ad\/js\/banner9232\.|\.widgets\.ad\?|\/ads\/generator\/|\/comscore\/streamsense\.|\/ads\/inner_|\/inner\-ads\-|\/inner\-ads\/|\/ajaxLogger_tracking_|\-analitycs\/\/metrica\.|\-analitycs\/metrica\.|\/ilivid\-ad\-|\/ads_door\.|\/trackingfilter\.json\?|\-ads\-180x|\/ads\-arc\.|\/ads\-cch\-|\/ads\.w3c\.|\/ads\/cbr\.|\/ads\/im2\.|\/ads\?apid|\/ems\/ads\.|\/ia\/ads\/|\/old\/ads\-|\/ome\.ads\.|\/sni\-ads\.|\/tit\-ads\.|\/v7\/ads\/|\/vld\.ads\?|\/bci\-ads\.|\/bci\-ads\/|\/ads\/125l\.|\/ads\/125r\.|\/ads\/3002\.|\/ads\/468a\.|\/ads\/728b\.|\/ads\/mpu2\?|\/ads\/narf_|\/ads_gnm\/|\/ast\/ads\/|\/cvs\/ads\/|\/dxd\/ads\/|\/esi\/ads\/|\/inv\/ads\/|\/mda\-ads\/|\/sbnr\.ads\?|\/smb\/ads\/|\/ss3\/ads\/|\/tmo\/ads\/|\/tr2\/ads\/|\/ads\-03\.|\/ads\/tso|\/ads\/daily\.|\/ads\/daily_|\.refit\.ads\.|\/1912\/ads\/|\/ads\-mopub\?|\/ads\-nodep\.|\/ads\/\?QAPS_|\/ads\/getall|\/ads\/gray\/|\/ads\/like\/|\/ads\/smi24\-|\/bauer\.ads\.|\/img3\/ads\/|\/ispy\/ads\/|\/kento\-ads\-|\/libc\/ads\/|\/subs\-ads\/|\/wire\/ads\/|_html5\/ads\.|\-ads\-530x85\.|\-intern\-ads\/|\/ads\-inside\-|\/ads\-intros\.|\/ads\.compat\.|\/ads\/acctid=|\/ads\/banid\/|\/ads\/bilar\/|\/ads\/box300\.|\/ads\/oscar\/|\/ads\?spaceid|\/ads_codes\/|\/ads_medrec_|\/ads_patron\.|\/ads_sprout_|\/cmlink\/ads\-|\/cssjs\/ads\/|\/digest\/ads\.|\/doors\/ads\/|\/dpics\/ads\/|\/gawker\/ads\.|\/minify\/ads\-|\/skin3\/ads\/|\/webapp\/ads\-|\?ads_params=|\/door\/ads\/|\-contrib\-ads\.|\-contrib\-ads\/|\-ads\-Feature\-|\/aderlee_ads\.|\/ads\-reviews\-|\/ads\.jplayer\.|\/ads\/250x120_|\/ads\/300x120_|\/ads\/behicon\.|\/ads\/labels\/|\/ads\/pencil\/|\/ads\/square2\.|\/ads\/square3\.|\/cactus\-ads\/|\/campus\/ads\/|\/develop\/ads_|\/expandy\-ads\.|\/outline\-ads\-|\/uplimg\/ads\/|\/xfiles\/ads\/|\/daily\/ads\/|\/ads\-sticker2\.|\/ads\.release\/|\/ads\/cnvideo\/|\/ads\/masthead_|\/ads\/mobiles\/|\/ads\/reskins\/|\/ads\/ringtone_|\/ads\/serveIt\/|\/central\/ads\/|\/cramitin\/ads_|\/gazette\/ads\/|\/hpcwire\/ads\/|\/jetpack\-ads\/|\/jsfiles\/ads\/|\/magazine\/ads\.|\/playerjs\/ads\.|\/taxonomy\-ads\.|\/ads\/webplayer\.|\/ads\/webplayer\?|\/ads\-mobileweb\-|\/ads\-segmentjs\.|\/ads\/leaderbox\.|\/ads\/proposal\/|\/ads\/sidedoor\/|\/ads\/swfobject\.|\/calendar\-ads\/|\/editable\/ads\/|\/releases\/ads\/|\/rule34v2\/ads\/|\/teaseimg\/ads\/|\-floorboard\-ads\/|\/ads\/htmlparser\.|\/ads\/postscribe\.|\/fileadmin\/ads\/|\/moneyball\/ads\/|\/permanent\/ads\/|\/questions\/ads\/|\/standalone\/ads\-|\/teamplayer\-ads\.|\/ads\/728x90above_|\/ads\/indexmarket\.|\/excellence\/ads\/|\/userimages\/ads\/|\-ads\/videoblaster\/|\/ads\-restrictions\.|\/ads\/displaytrust\.|\/ads\/scriptinject\.|\/ads\/writecapture\.|\/colorscheme\/ads\/|\/configspace\/ads\/|\/homeoutside\/ads\/|\/incotrading\-ads\/|\/ads\/checkViewport\.|\/ads\/welcomescreen\.|\/photoflipper\/ads\/|\/ads\/generatedHTML\/|\/customcontrols\/ads\/|\/ads\/contextuallinks\/|\/ads\/elementViewability\.|\/metrics\-VarysMetrics\.|\/ads\/exo_|\/hosting\/ads\/|\/tracking\/setTracker\/|\/track\.php\?referrer=|\/ads\-scroller\-|\/adv\.css\?|\/css\/adv\.|\/ads\/original\/|\/ads\-blogs\-|\/dynamic\-ad\-|\/dynamic\-ad\/|\/button_ads\/|\/carousel_ads\.|\/adv\.jsp|\-advert_August\.|\/ad_onclick\.|\/include\/adsdaq|\/qpon_big_ad|\/watchit_ad\.|\.net\/flashads|\/track_general_stat\.|\.am\/adv\/|\/wp\-content\/plugins\/bookingcom\-banner\-creator\/|\/adv\-scroll\-|\/adv\-scroll\.|\/04\/ads\-|\/ads\-04\.|\/big\-ad\-switch\-|\/big\-ad\-switch\/|=big\-ad\-switch_|\/scripts\/AdService_|\/ads\/adv\/|\/adv\/ads\/|\/tncms\/ads\/|\/log_zon_img\.|\/ads\/popup\.|\/ads\/popup_|\-popup\-ads\-|\/ad\/special\.|\/special_ad\.|\/shared\/ads\.|\/shared\/ads\/|\/tracking\/comscore\/|\/dmn\-advert\.|\/smedia\/ad\/|\/track_yt_vids\.|\/tracker\/trackView\?|\-ad\-reload\.|\-ad\-reload\/|\/ad\-sovrn\.|\/plugins\/status\.gif\?|\/google\-nielsen\-analytics\.|\.cfm\?advideo%|\/traffic\-source\-cookie\.|\/traffic\-source\-cookie\/|\/intermediate\-ad\-|\/gen_ads_|\/ads\/create_|\/event\/rumdata\?|\/cgi\-sys\/count\.cgi\?df=|\/simple\-tracking\?|\?eventtype=request&pid=|\/php\-stats\.phpjs\.php\?|\/php\-stats\.recjs\.php\?|\/ads\-05\.|\/ad\/window\.php\?|\/affiliate\-tracker\.|\/tops\.ads\.|\/tracking\/digitalData\.|\/magic\-ads\/|\/ad\-callback\.|\/ads\/drive\.|\/country_ad\.|=get_preroll_cookie&|\/meas\.ad\.pr\.|\/ads\-06\.|\/ads_event\.|\/ads\.pbs|\/event\?t=view&|\/layout\/ads\/|\/monetization\/ads\-|\/log\?sLog=|\/ad_links\/|\/stuff\/ad\-|\/scripts\/tracking\.js|\/cross\-domain\-cookie\?|\/silver\/ads\/|\/json\/tracking\/|\/analys\/dep\/|\/ads\/motherless\.|\/lead\-tracking\.|\/lead\-tracking\/|\/bsc_trak\.|\/logo\-ads\.|\/logo\/ads_|\/GoogleAnalytics\?utmac=|\/banner\.ws\?|\/ad\.cgi\?|\.cgi\?ad=|\/cgi\/ad_|\/tracker\-ev\-sdk\.js|\/ima\/ads_|\/tracking\.relead\.|\/gen\-ad\-|\/ads\-01\.|\/AdCookies\.js|\/xtanalyzer_roi\.|\/ads\/configuration\/|\/iva_thefilterjwanalytics\.|\/trackv&tmp=|\/adblock\?id=|\/storage\/adv\/|\/track\-compiled\.js|\/entry\.count\.image\?|\/affiliate\-track\.|\/affiliate\.track\?|\/affiliate\/track\?|\/fm\-ads1\.|\/assets\/ads3\-|\/linktracking\.|\/ads\-leader$|\/Ad\/premium\/|\/datacapture\/track|\/stat\/eventManager\/|&adserv=|\.adserv\/|\/adserv\.|\/adserv\/|\/adserv_|\/js_log_error\.|\-strip\-ads\-|\/cookie\.crumb|\/cookie\/visitor\/|\/ad\/extra\/|\/ad\/extra_|\/adbl_dtct\.|\/khan_analystics\.js|\/gcui_vidtracker\/|\/ADV\/Custom\/|\/adenc\.|\/adenc_|\/seosite\-tracker\/|\/bftv\/ads\/|\/ad\-half_|\/tracker\-config\.js|\/sbtracking\/pageview2\?|\/atcode\-bannerize\/|\/styles\/ads\.|\/styles\/ads\/|\/buyer\/dyad\/|\/propagate_cookie\.|\/ads\/select\/|\/wp\-content\/mbp\-banner\/|\/mad\.aspx\?|\/analiz\.php3\?|\/xml\/ad\/|\/ads\-beacon\.|\/ads\/beacon\.|\/beacon\/ads\?|\/Affiliate\-Banner\-|\/tracking\/track\.jsp\?|\/analytics\.json\?|\-Results\-Sponsored\.|\/admvn_pop\.|\-ads\-master\/|\/showcode\?adids=|\/A\-LogAnalyzer\/|\/session\-tracker\/tracking\-|\/related\-ads\.|\/compiled\/ads\-|_ajax\/btrack\.php\?|\/addon\/analytics\/|\/ads\-07\.|\-ads\-tracking\-|\/ads_tracking\.|\/tracking\/ads\.|\/ad%20banners\/|\/add_page_view\?|\/ads\/profile\/|\-ads\.generated\.|\/analytics\.config\.js|\/fora_player_tracking\.|\/stats_brand\.js|\/2011\/ads\/|\/jkidd_cookies\?|\/track\/pix2\.asp\?|\/adim\.html\?ad|\/ads\/community\?|\/tracking\-jquery\-shim\.|\/AdBlockDetection\/scriptForGA\.|\/ads\/real_|\/ads\/imbox\-|\/stats\/Logger\?|_stats\/Logger\?|\/ad\-iptracer\.|\/javascript\/ads\.|\/javascript\/ads\/|\/demo\/ads\/|\/analytics\.bundled\.js|\/blogtotal_stats_|\/comscore_stats\.|\/ads~adsize~|\/ads\-rectangle\.|\/ads\/rectangle_|\/jsc\/ads\.|_ads_v8\.|\/tracking\/user_sync_widget\?|\/TILE_ADS\/|\/ad\/p\/jsonp\?|\/sitefiles\/ads\/|\/ad\/select\?|\/stats\/adonis_|\/3pt_ads\.|\/fea_ads\.|\/gtv_ads\.|\/qd_ads\/|\/ads\.bundle\.|\/bundle\/ads\.|\-ads\/ad\-|\/ads\/ad\-|\/ads\/ad\.|\/ads\/ad_|\/ads_ad_|\/adblade\-publisher\-tools\/|\-Web\-Advert\.|\/ads\/freewheel\/|\/digg_ads\.|\/digg_ads_|\/eco_ads\/|\/flag_ads\.|\/ges_ads\/|\/m0ar_ads\.|\/miva_ads\.|_ads_Home\.|_ads_only&|\/ad_cache\/|\/adlabs\.js|\/defer_ads\.|\/ifrm_ads\/|\/chorus_ads\.|\/torget_ads\.|_ads_single_|\/wp\-content\/plugins\/automatic\-social\-locker\/|\/ads\/dhtml\/|_ads_updater\-|_rightmn_ads\.|_ads\/inhouse\/|\/affiliate\/ad\/|_affiliate_ad\.|\/ads_premium\.|\/ads_tracker\.|\/ads\/tracker\/|\-ad\-category\-|\?category=ad&|\/adm_tracking\.js|\/inhouse_ads\/|\/included_ads\/|_ads_framework\.|\/statistics\/metrica\.|\/ads_common_library\.|\/autotrack\.carbon\.js|\/track\/\?site|\/track\/site\/|\/imagecache_ads\/|\/WritePartnerCookie\?|\-adverts\.libs\.|\/videostreaming_ads\.|\/rcom\-ads\-|\/rcom\-ads\.|\-Advert\-JPEG\-|\/serv\.ads\.|\/msn\-exo\-|\/client\-event\.axd\?|\/ad_flash\/|\/data\/ads\/|_ads_contextualtargeting_|\/u\-ads\.|\/u\/ads\/|\/tracker\-r1\.js|\/Online\-Adv\-|\/statistics\/pageStat\/|\/images2\/ads\/|\/adlog\.php\?|\/curveball\/ads\/|\/ads\/rail\-|\-rail\-ads\.|\-rail\-ads\/|\/log\/jserr\.php|\/ez_aba_load\/|\/ads\/frontpage\/|\/ads\/rect_|\/vision\/ads\/|\.adbutler\-|\/adbutler\-|\/adbutler\/|\/ignite\.partnerembed\.js|\/tracker\-setting\.js|\/flash\/ad\/|\/flash\/ad_|\/arms\-datacollectorjs\/|\/ad1\/index\.|\/ad_config\.|\/statistics\.aspx\?profile|\/ad_companion\?|\/companion_ad\.|\/wp\-click\-track\/|\/jquery_FOR_AD\/|\/log\-ads\.|\/beacon\-cookie\.|\/ads\-02\.|\/Logs\/other\?data=|\/fm\-ads3\.|\/ads\/track\.|\/ads\/track\/|\/china\-ad\.|\.eu\/adv\/|\/track\.ads\/|\/admantx\-|\/admantx\.|\/admantx\/|\/banner\/rtads\/|\/17\/ads\/|\/adblock\?action=|\/banners\/affiliate\/|\/tracking\/addview\/|\/newimages\/ads\/|\/global\/ad\/|\/videolog\?vid=|\/ad\/no_cookie\?|&strategy=adsense&|\/doubleclick_head_tag_|\/adobe\/VideoHeartbeat\-|\/tracking\/xtcore\.|_sponsor_logic\.|\.info\/ad_|\/ad\.info\.|\/securepubads\.|\/impressions\/(?=([\s\S]*?\/track))\1|\/track\/(?=([\s\S]*?&CheckCookieId=))\2|\/track\/(?=([\s\S]*?&siteurl=))\3|\/promoredirect\?(?=([\s\S]*?&campaign=))\4(?=([\s\S]*?&zone=))\5|\/images\/a\.gif\?(?=([\s\S]*?=))\6|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?cpx\.to))\7|\.us\/ad\/(?=([\s\S]*?\?))\8|\$csp=child\-src 'none'; frame\-src (?=([\s\S]*?; worker\-src 'none',domain=adfreetv\.ch$ddmix\.net$extratorrent\.cd$gofile\.io$hq\-porns\.com$intactoffers\.club$myfeed4u\.net$reservedoffers\.club$skyback\.ru$szukajka\.tv$thepiratebay\.cr$thepiratebay\.org$thepiratebay\.red$thevideo\.cc$thevideo\.ch$thevideo\.io$thevideo\.me$thevideo\.us$tvad\.me$vidoza\.net$vidup\.me))\9|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?mc\.yandex\.ru))\10|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?revcontent\.com))\11|\/widgets\/adverts\/(?=([\s\S]*?\.))\12|\$csp=script\-src 'self' (?=([\s\S]*? 'unsafe\-inline',domain=fflares\.com$fileflares\.com$ibit\.to$piratbaypirate\.link$unblocktheship\.org$noobnoob\.rocks$indiaproxydl\.org$magnetbay\.eu$airproxyproxy\.pw$thepirate\.xyz$pietpiraat\.org$ahoypirate\.in$tpb\.tw$proxyindia\.net$thepiratebay\.blue$ahoypiratebaai\.eu$pirate\.bet$airproxytpb\.red$ikwildepiratebay\.xyz$piratebay\.tel$bayception\.pw$piratebay\.town$superbay\.link$thepiratebay\.kiwi$tpb\.one$baypirateproxy\.pw$rarbgmirrored\.org$rarbgmirror\.org$rarbg\.to$rarbgaccess\.org$rarbgmirror\.com$rarbgmirror\.xyz$rarbgproxy\.org$rarbgprx\.org$mrunlock\.pro$downloadpirate\.com$prox4you\.xyz$123unblock\.info$nocensor\.icu$unlockproject\.live$pirateproxy\.bet$thepiratebay\.vip$theproxybay\.net$thepiratebay\.tips$thepiratebay10\.org$prox1\.info$kickass\.vip$torrent9\.uno$torrentsearchweb\.ws$pirateproxy\.app$ukpass\.co$theproxybay\.net$thepiratebay\.tips$prox\.icu$proxybay\.ga$pirateproxy\.life$piratebae\.co\.uk$berhampore\-gateway\.ml$ikwilthepiratebay\.org$thepiratebay10\.org$bayfortaiwan\.online$unblockthe\.net$cruzing\.xyz))\13|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?contextual\.media\.net))\14|\/cdn\-cgi\/pe\/bag\?r(?=([\s\S]*?cpalead\.com))\15|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?viglink\.com))\16|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?static\.getclicky\.com%2Fjs))\17|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?googleadservices\.com))\18|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?clkrev\.com))\19|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?nr\-data\.net))\20|\$csp=child\-src 'none'; frame\-src 'self' (?=([\s\S]*?; worker\-src 'none',domain=fileone\.tv$theappguruz\.com))\21|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?google\-analytics\.com%2Fanalytics\.js))\22|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?content\.ad))\23|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?geoiplookup))\24|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?hs\-analytics\.net))\25|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?chartbeat\.js))\26|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?cdn\.onthe\.io%2Fio\.js))\27|\/cdn\-cgi\/pe\/bag\?r(?=([\s\S]*?pubads\.g\.doubleclick\.net))\28|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?log\.outbrain\.com))\29|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?adsnative\.com))\30|\/cdn\-cgi\/pe\/bag2\?r\[\]=(?=([\s\S]*?eth\-pocket\.de))\31|\?AffiliateID=(?=([\s\S]*?&campaignsVpIds=))\32|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?bounceexchange\.com))\33|\/\?com=visit(?=([\s\S]*?=record&))\34|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.qualitypublishers\.com))\35|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.worldoffersdaily\.com))\36|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?eclkmpbn\.com))\37|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?eclkspsa\.com))\38|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.codeonclick\.com))\39|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.zergnet\.com))\40|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?zwaar\.org))\41|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.amazonaws\.com))\42(?=([\s\S]*?secure\.js))\43|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.content\-ad\.net))\44|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?revdepo\.com))\45|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?bnserving\.com))\46|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?linksmart\.com))\47|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?puserving\.com))\48|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?intellitxt\.com))\49|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?\.speednetwork1\.com))\50|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?az708531\.vo\.msecnd\.net))\51|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?scorecardresearch\.com))\52|\/Redirect\.(?=([\s\S]*?MediaSegmentId=))\53|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?newrelic\.com))\54|\/Log\?(?=([\s\S]*?&adID=))\55|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?juicyads\.com))\56|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?\.google\-analytics\.com))\57|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?adk2\.co))\58|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?pipsol\.net))\59|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?popcash\.net))\60|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?mellowads\.com))\61|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?quantserve\.com))\62|^javascript\:(?=([\s\S]*?window\.location))\63|\/affiliates\/(?=([\s\S]*?\/show_banner\.))\64|\/impressions\/(?=([\s\S]*?\/creative\.png\?))\65|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?popads\.net))\66|\?zoneid=(?=([\s\S]*?_bannerid=))\67|\/cdn\-cgi\/pe\/bag2\?(?=([\s\S]*?adsrvmedia))\68|=event&(?=([\s\S]*?_ads%))\69|\/g00\/(?=([\s\S]*?\/clientprofiler\/adb))\70|\/analytics\/(?=([\s\S]*?satellitelib\.js))\71|\/cdn\-cgi\/pe\/bag2\?r(?=([\s\S]*?\.adroll\.com))\72)/i;
var bad_url_parts_flag = 2629 > 0 ? true : false;  // test for non-zero number of rules
    
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
