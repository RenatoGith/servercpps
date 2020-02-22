/*	swffit v1.0 (03/25/2008) <http://swffit.millermedeiros.com/>
	Copyright (c) 2008 Miller Medeiros <http://www.millermedeiros.com/>
	This software is released under the MIT License <http://www.opensource.org/licenses/mit-license.php>
*/

var NS=(navigator.appName=='Netscape')?true:false;var ft;var mw;var mh;var xw;var xh;var xc;function swffit(t,w,h,_w,_h,c){if(t&&w&&h){ft=t;mw=w;mh=h;xw=_w;xh=_h;xc=(c||c==null)?true:false;if(swfobject.isDomLoaded){startFit()}else{swfobject.addDomLoadEvent(startFit)}}}function gEBI(x){return x}function startFit(){document.getElementsByTagName('html')[0].style.height='98%';document.body.style.margin='0';document.body.style.padding='0';document.body.style.height='98%';if(swfobject.getObjectById(ft)){ft=swfobject.getObjectById(ft)}else{ft=(NS)?document.getElementById(ft).getElementsByTagName('object')[0]:document.getElementById(ft)}gEBI(ft).style.position='relative';window.onresize=fit;fit()}function fit(){iw=(NS)?window.innerWidth:document.body.clientWidth;ih=(NS)?window.innerHeight:document.body.clientHeight;if(iw>xw&&xw){gEBI(ft).style.width=xw+'px';if(xc){gEBI(ft).style.left='50%';gEBI(ft).style.marginLeft=-(xw/2)+'px'}}else{if(iw>mw&&(iw<xw||!xw)){gEBI(ft).style.width='100%'}else{gEBI(ft).style.width=mw+'px'}if(xc){gEBI(ft).style.left='auto';gEBI(ft).style.marginLeft='0'}}if(ih>xh&&xh){gEBI(ft).style.height=xh+'px';if(xc){gEBI(ft).style.top='49%';gEBI(ft).style.marginTop=-(xh/2)+'px'}}else{if(ih>mh&&(ih<xh||!xh)){gEBI(ft).style.height='99%'}else{gEBI(ft).style.height=mh+'px'}if(xc){gEBI(ft).style.top='auto';gEBI(ft).style.marginTop='0'}}};
/*
     FILE ARCHIVED ON 06:08:25 May 28, 2010 AND RETRIEVED FROM THE
     INTERNET ARCHIVE ON 21:43:59 Oct 12, 2017.
     JAVASCRIPT APPENDED BY WAYBACK MACHINE, COPYRIGHT INTERNET ARCHIVE.

     ALL OTHER CONTENT MAY ALSO BE PROTECTED BY COPYRIGHT (17 U.S.C.
     SECTION 108(a)(3)).
*/