import xbmc, xbmcgui, xbmcplugin
import urllib2,urllib,cgi, re, urlresolver
import urlparse
import HTMLParser
import xbmcaddon
import time
from operator import itemgetter
import requests
import traceback, sys,cookielib,json
__addon__       = xbmcaddon.Addon()
__addonname__   = __addon__.getAddonInfo('name')
__icon__        = __addon__.getAddonInfo('icon')
addon_id = 'plugin.video.serialzone'
selfAddon = xbmcaddon.Addon(id=addon_id)
  
 
def addLink(name,url,iconimage):
	ok=True
	liz=xbmcgui.ListItem(name, iconImage="DefaultVideo.png", thumbnailImage=iconimage)
	liz.setInfo( type="Video", infoLabels={ "Title": name } )
	ok=xbmcplugin.addDirectoryItem(handle=int(sys.argv[1]),url=url,listitem=liz)
	return ok
# end function


def addDir(name,url,mode,iconimage	,showContext=False, showLiveContext=False,isItFolder=True):
#	print name
#	name=name.decode('utf-8','replace')
	h = HTMLParser.HTMLParser()
	name= h.unescape(name.decode("utf8")).encode("ascii","ignore")
	#print  name
	#print url
	#print iconimage
	u=sys.argv[0]+"?url="+urllib.quote_plus(url)+"&mode="+str(mode)+"&name="+urllib.quote_plus(name)
	ok=True
#	print iconimage
	liz=xbmcgui.ListItem(name, iconImage="DefaultFolder.png", thumbnailImage=iconimage)
	liz.setInfo( type="Video", infoLabels={ "Title": name } )

	if showContext==True:
		cmd1 = "XBMC.RunPlugin(%s&linkType=%s)" % (u, "DM")
		cmd2 = "XBMC.RunPlugin(%s&linkType=%s)" % (u, "LINK")
		cmd3 = "XBMC.RunPlugin(%s&linkType=%s)" % (u, "Youtube")
		liz.addContextMenuItems([('Play Youtube video',cmd3),('Play DailyMotion video',cmd1),('Play Tune.pk video',cmd2)])
	
	if showLiveContext==True:
		cmd1 = "XBMC.RunPlugin(%s&linkType=%s)" % (u, "RTMP")
		cmd2 = "XBMC.RunPlugin(%s&linkType=%s)" % (u, "HTTP")
		liz.addContextMenuItems([('Play RTMP Steam (flash)',cmd1),('Play Http Stream (ios)',cmd2)])
	
	ok=xbmcplugin.addDirectoryItem(handle=int(sys.argv[1]),url=u,listitem=liz,isFolder=isItFolder)
	return ok
# end function
	


def get_params():
	param=[]
	paramstring=sys.argv[2]
	if len(paramstring)>=2:
		params=sys.argv[2]
		cleanedparams=params.replace('?','')
		if (params[len(params)-1]=='/'):
			params=params[0:len(params)-2]
		pairsofparams=cleanedparams.split('&')
		param={}
		for i in range(len(pairsofparams)):
			splitparams={}
			splitparams=pairsofparams[i].split('=')
			if (len(splitparams))==2:
				param[splitparams[0]]=splitparams[1]
				
	return param
# end function



def Addtypes():
	#2 is series=3 are links
	addDir('Bengali' ,'http://bengali.serialzone.in/', 2, '')
	addDir('Hindi' ,'http://hindi.serialzone.in/', 2,'')
	addDir('Kannada' ,'http://kannada.serialzone.in/' , 2,'')
	addDir('Malayalam' ,'http://malayalam.serialzone.in/', 2,'')
	addDir('Marathi' ,'http://marati.serialzone.in/', 2, '')
	addDir('Tamil' ,'http://tamil.serialzone.in/', 2, '')
	addDir('Telugu' ,'http://telugu.serialzone.in/', 2, '')
	return


def ShowSettings(Fromurl):
	selfAddon.openSettings()
#end function


def AddTVChannels(Fromurl):
	#print "Incoming: %s" %Fromurl
	try:
	   req = urllib2.Request(Fromurl)
	   req.add_header('User-Agent','Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B314 Safari/531.21.10')
	   response = urllib2.urlopen(req)
	   link=response.read()
	   response.close()
	except:
           print "Error opening URL"
	   return(0)

	#print link
	print "add TV channels"
        idx1= link.index("<div class=\"nav\">")
        #print "INDEX1: %s" %idx1
        templ=link[idx1:]
        #print "TEMPL: %s" %templ
        idx2=templ.index(r"</div>")
        #print "INDEX2: %s" %idx2
        new_link=templ[:idx2+6]
        #print "LINK: %s" %new_link

        # first level to match on nav pttern
	#regstring='<div class="nav"><ul>  (.*?)<a href="(.*?)">(.*?)<\/a>(.*?)<\/ul><\/div>'
	#match_temp =re.findall(regstring, new_link)
        #print "Match - Lev 1: ",match_temp

	#take the fourth element
	#link_temp=match_temp[0][3]
	regstring='<a href="(.*?)">(.*?)<\/a>'
	match = re.findall(regstring, new_link)
     
	print "Match - Lev 2: ",match

	for cname in match:
           # ignore online games from showing on XBMC/KODI - take all other channel info
	    if 'gallery' in cname[1]:
                continue # continue to next entry

            elif "HOME" in cname[1]:
                continue # continue to next entry

	    elif "snav" in cname[1]:
                continue # continue to next entry
	
            elif cname[1] not in ('GAMES','ACTRESS','ACTOR','Games','Actor'):
               #print "Name:%s\nURLI:%s\n" %(cname[1],cname[0])
               URLI=''
               if 'http:' in cname[0]:
                  URLI='%s' %(cname[0])
               else:
		  URLI="%s%s" %(Fromurl,cname[0])

               #print "addDir('%s', '%s', 3, '') " %(cname[1],URLI)
	       addDir(cname[1] ,URLI, 3, '')#url,name,jpg_name,url,mode,icon

	return
#end function


def AddSeries(Fromurl):
    #print "Incoming URL:",Fromurl
    try:
#       req = urllib2.Request(Fromurl)
#       req.add_header('User-Agent','Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B314 Safari/531.21.10')
#       response = urllib2.urlopen(req)
#       link=response.read()
#       response.close()
       #using requests module as urllib2 not returning full page due to content size not being sent correctly from the server!
       headers = {'user-agent': 'Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B314 Safari/531.21.10'}
       r = requests.get(Fromurl,headers=headers)
       
       link=r.text
    except:
        print "Error opening URL"
        return(0)

    print link, len(link)
    print "addshows"

    regstring='<div class="serial">(.*?)<\/div>'
    match_temp=re.findall(regstring, link)

    print "Num elements: ",len(match_temp)
    print "Match_items: ",match_temp
    for entries in match_temp:
        # walk thru matched patterns to find sub-pattern
        print "MATCH ENTRY LEV1: ",entries
            #idx1= entries.index('<img src=')
            #rint "INDEX1: %s" %idx1
            #mpl=entries[idx1:]
            #rint "TEMPL: %s" %templ
            #ntries=templ
        subreg_str='<img src="(.*?)".*?<div class="title"><a href="(.*?)">(.*?)<\/a>'
        match2=re.findall(subreg_str, entries)
        print match2

        for cname in match2:
        #print "LEV 2 match: ",cname
        # ignore online games from showing on XBMC/KODI - take all other series info
            URLI=cname[0]
            if 'http:' not in URLI:
               URLI=Fromurl+cname[0]
            else:
               URLI=cname[0]

            SHOWURL=cname[1]
            SHOWURL+="?view=all"
            if cname[2] not in ('The Kings League: Odyssey','TT Racer'):
               #print "Name:%s\nURLI:%s\nICON:%s\n" %(cname[2], SHOWURL, URLI)
               addDir(cname[2] , SHOWURL, 4, URLI)#url,name,jpg_name,url,mode,icon
            # end inner-loop
    # end outer-loop
    return
#end function


def AddEnteries(Fromurl):
	#print "FROMURL: " ,Fromurl
	try:
	   req = urllib2.Request(Fromurl)
	   req.add_header('User-Agent','Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B314 Safari/531.21.10')
	   response = urllib2.urlopen(req)
	   link=response.read()
	   response.close()
	except:
	   print "Error opening URL"
	   return(0)

	#print link
	#print "adding shows"

        # new match string
	match =re.findall('<div class="episode" id=\'h3_(.*?)\' ><a href=(.*?)><h4>(.*?)<\/h4></a><\/div>', link, re.M|re.DOTALL)

#	#print "MATCHED ARRAY: ", match
	h = HTMLParser.HTMLParser()

	for cname in match:
	    # ignore online games - take only the dates
            if cname[2] not in ('The Kings League: Odyssey', 'TT Racer'):
               #print "Name:%s\nURLI:%s\nICON:%s\n" %(cname[0],cname[1],cname[2])
	       addDir(cname[2] ,cname[0] ,5, "",isItFolder=False) #(name, url, mode, icon)
	return
# end function

	
def AddChannels(liveURL):
	req = urllib2.Request(liveURL)
	req.add_header('User-Agent','Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B314 Safari/531.21.10')
	response = urllib2.urlopen(req)
	link=response.read()
	response.close()
#	print link
#	match=re.compile('<param name="URL" value="(.+?)">').findall(link)
#	match=re.compile('<a href="(.+?)"').findall(link)
#	match=re.compile('onclick="playChannel\(\'(.*?)\'\);">(.*?)</a>').findall(link)
#	match =re.findall('onclick="playChannel\(\'(.*?)\'\);">(.*?)</a>', link, re.DOTALL|re.IGNORECASE)
#	match =re.findall('onclick="playChannel\(\'(.*?)\'\);".?>(.*?)</a>', link, re.DOTALL|re.IGNORECASE)
#	match =re.findall('<div class=\"post-title\"><a href=\"(.*?)\".*<b>(.*)<\/b><\/a>', link, re.IGNORECASE)
#	match =re.findall('<img src="(.*?)" alt=".*".+<\/a>\n*.+<div class="post-title"><a href="(.*?)".*<b>(.*)<\/b>', link, re.UNICODE)

	match =re.findall('<div class="videopart">\s*<div class="paneleft">\s*<a.*href="(.*?)".*title="(.*?)".*<img.*src="(.*?)"', link,re.M)

	print match
	h = HTMLParser.HTMLParser()
	for cname in match:
		addDir(cname[1] ,cname[0] ,7,cname[2], False, True)		#name,url,mode,icon
	return	
# end function
	
def kodiJsonRequest(params):
    data = json.dumps(params)
    request = xbmc.executeJSONRPC(data)

    try:
        response = json.loads(request)
    except UnicodeDecodeError:
        response = json.loads(request.decode('utf-8', 'ignore'))

    try:
        if 'result' in response:
            return response['result']
        return None
    except KeyError:
        logger.warn("[%s] %s" % (params['method'], response['error']['message']))
        return None


def setKodiProxy(proxysettings=None):

    if proxysettings==None:
        print 'proxy set to nothing'
        xbmc.executeJSONRPC('{"jsonrpc":"2.0", "method":"Settings.SetSettingValue", "params":{"setting":"network.usehttpproxy", "value":false}, "id":1}')
    else:
        
        ps=proxysettings.split(':')
        proxyURL=ps[0]
        proxyPort=ps[1]
        proxyType=ps[2]
        proxyUsername=None
        proxyPassword=None
         
        if len(ps)>3 and '@' in proxysettings:
            proxyUsername=ps[3]
            proxyPassword=proxysettings.split('@')[-1]

        print 'proxy set to', proxyType, proxyURL,proxyPort
        xbmc.executeJSONRPC('{"jsonrpc":"2.0", "method":"Settings.SetSettingValue", "params":{"setting":"network.usehttpproxy", "value":true}, "id":1}')
        xbmc.executeJSONRPC('{"jsonrpc":"2.0", "method":"Settings.SetSettingValue", "params":{"setting":"network.httpproxytype", "value":' + str(proxyType) +'}, "id":1}')
        xbmc.executeJSONRPC('{"jsonrpc":"2.0", "method":"Settings.SetSettingValue", "params":{"setting":"network.httpproxyserver", "value":"' + str(proxyURL) +'"}, "id":1}')
        xbmc.executeJSONRPC('{"jsonrpc":"2.0", "method":"Settings.SetSettingValue", "params":{"setting":"network.httpproxyport", "value":' + str(proxyPort) +'}, "id":1}')
        
        
        if not proxyUsername==None:
            xbmc.executeJSONRPC('{"jsonrpc":"2.0", "method":"Settings.SetSettingValue", "params":{"setting":"network.httpproxyusername", "value":"' + str(proxyUsername) +'"}, "id":1}')
            xbmc.executeJSONRPC('{"jsonrpc":"2.0", "method":"Settings.SetSettingValue", "params":{"setting":"network.httpproxypassword", "value":"' + str(proxyPassword) +'"}, "id":1}')
def getConfiguredProxy():
    proxyActive = kodiJsonRequest({'jsonrpc': '2.0', "method":"Settings.GetSettingValue", "params":{"setting":"network.usehttpproxy"}, 'id': 1})['value']
    print 'proxyActive',proxyActive
    proxyType = kodiJsonRequest({'jsonrpc': '2.0', "method":"Settings.GetSettingValue", "params":{"setting":"network.httpproxytype"}, 'id': 1})['value']

    if proxyActive: # PROXY_HTTP
        proxyURL = kodiJsonRequest({'jsonrpc': '2.0', "method":"Settings.GetSettingValue", "params":{"setting":"network.httpproxyserver"}, 'id': 1})['value']
        proxyPort = unicode(kodiJsonRequest({'jsonrpc': '2.0', "method":"Settings.GetSettingValue", "params":{"setting":"network.httpproxyport"}, 'id': 1})['value'])
        proxyUsername = kodiJsonRequest({'jsonrpc': '2.0', "method":"Settings.GetSettingValue", "params":{"setting":"network.httpproxyusername"}, 'id': 1})['value']
        proxyPassword = kodiJsonRequest({'jsonrpc': '2.0', "method":"Settings.GetSettingValue", "params":{"setting":"network.httpproxypassword"}, 'id': 1})['value']

        if proxyUsername and proxyPassword and proxyURL and proxyPort:
            return proxyURL + ':' + str(proxyPort)+':'+str(proxyType) + ':' + proxyUsername + '@' + proxyPassword
        elif proxyURL and proxyPort:
            return proxyURL + ':' + str(proxyPort)+':'+str(proxyType)
    else:
        return None
        
        
def playmediawithproxy(media_url, name, iconImage,proxyip,port,progress):

    progress.create('Progress', 'Playing with custom proxy')
    progress.update( 50, "", "setting proxy..", "" )
    proxyset=False
    existing_proxy=''
    try:
        
        existing_proxy=getConfiguredProxy()
        print 'existing_proxy',existing_proxy
        #read and set here
        setKodiProxy( proxyip + ':' + port+':0')

        print 'proxy setting complete', getConfiguredProxy()
        proxyset=True
        progress.update( 80, "", "setting proxy complete, now playing", "" )
        progress.close()
        progress=None
        import  CustomPlayer
        player = CustomPlayer.MyXBMCPlayer()
        listitem = xbmcgui.ListItem( label = str(name), iconImage = iconImage, thumbnailImage = xbmc.getInfoImage( "ListItem.Thumb" ), path=media_url )
        player.play( media_url,listitem)
        xbmc.sleep(1000)
        while player.is_active:
            xbmc.sleep(200)
    except:
        traceback.print_exc()
    if progress:
        progress.close()
    if proxyset:
        print 'now resetting the proxy back'
        setKodiProxy(existing_proxy)
        print 'reset here'
    return ''
    
def PlayShowLink ( url ): 
    #	url = tabURL.replace('%s',channelName);
    print "URL: %s" %url
    #regstring='http:\/\/(.*?)\/admin'
        #match=re.findall(regstring, url)
        
    url2='http://serialzone.in/admin/AjaxProcess.php?cfile=load_video&id=%s&param=value&_=%s' % (url, time.time())
    print url2
    req = urllib2.Request(url2)
    req.add_header('User-Agent', 'Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B314 Safari/531.21.10')
    response = urllib2.urlopen(req)
    link=response.read()
    response.close()

    #        print "LINK READ: ", link
    match =re.findall('embed\/(.*?)\?', link)
    #        print "MATCH: ",match,"\t\tMATCH LEN: ",len(match)
        
    if len(match)==0:
    #		print 'not found trying again'
        match =re.findall('yp\(\'(.*?)\'', link)
    #	print "LINK: ",link
    #        print "MATCH: ",match

    time1=2000
    line1 = "Playing Youtube Link"
    xbmc.executebuiltin('Notification(%s, %s, %d, %s)'%(__addonname__,line1, time1, __icon__))

    youtubecode=match[0]

    progress = xbmcgui.DialogProgress()
    progress.create('Progress', 'Checking if Proxy Required?')
    progress.update( 20, "", "Getting Urls..")

    liveUrl='https://m.youtube.com/watch?v=%s'%youtubecode
    stringFailed='The uploader has not made this video available in your country'
    req = urllib2.Request(liveUrl)
    req.add_header('User-Agent', 'Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3')
    response = urllib2.urlopen(req)
    link=response.read()
    response.close()
    if stringFailed in link and 'googlevideo' not in link:        
        try:
            proxyserver=selfAddon.getSetting('ProxyServer')#:8080
            proxyport=str(selfAddon.getSetting('ProxyPort'))
            try:
                vquality=int(selfAddon.getSetting('youtubevideo'))
                print vquality
                vquality="hd720|medium|small".split('|')[vquality]
            except:
                vquality="medium"
            print proxyserver,proxyport,vquality
            progress.update( 60, "", "Yes proxy required, using %s:%s"%(proxyserver,str(proxyport)))
            ##use US proxy and play with it
            
            cookieJar = cookielib.LWPCookieJar()
            cookie_handler = urllib2.HTTPCookieProcessor(cookieJar)
            opener = urllib2.build_opener(cookie_handler, urllib2.HTTPBasicAuthHandler(), urllib2.HTTPHandler(),urllib2.ProxyHandler({ 'https'  : '%s:%s'%(proxyserver,proxyport)}))
            req = urllib2.Request(liveUrl)
            req.add_header('User-Agent','Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3')
            response = opener.open(req,timeout=20)            
            link=response.read()
            response.close()
            print link
            progress.update( 90, "", "Got the Link, Now playing via proxy" )
            pat2='\\\\?u0026quality=(.*?)\\\\.*?url=(http.*?videoplayback.*?),'
            pat='url_encoded_fmt_stream_map\\\\"\\: (.*?), '
            final_url=re.findall(pat,link)
            if len(final_url)==0:
                return
                #final_url=re.findall(pat2,link)
            final_url=final_url[0].split(',')
            print final_url
            print 'final_url',final_url
            qarray=[]
            for sss in final_url:
                url=urllib.unquote(sss.split('url=')[1].split('\\')[0])
                qlt=sss.split('quality=')[1].split(',')[0].split('\\')[0]
                qarray.append([url,qlt])
            urltoplay=None
            if len(qarray)==0:
                progress.update( 99, "", "FAILED, proxy issues or link resolution problem" )
                time1=2000
                line1 = "GeoBocked:Proxy issues or link resolution problem"
                xbmc.executebuiltin('Notification(%s, %s, %d, %s)'%(__addonname__,line1, time1, __icon__))
                return 
            print 'qarray',qarray
            if len(qarray)>1:
                for uu in qarray:
                    if uu[1]==vquality and ',' not in uu[0]:
                        urltoplay=uu[0]
                        print 'quality selected',uu
            if not urltoplay:
                print 'default quality selected',final_url[0]
                urltoplay=final_url[0][0]
                
            urltoplay=urllib.unquote(urltoplay)
            print 'urltoplay',urltoplay
            playmediawithproxy(urltoplay,name,'',proxyserver,proxyport,progress)
        except: traceback.print_exc(file=sys.stdout)
        return ''

    uurl = 'plugin://plugin.video.youtube/play/?video_id=%s' % youtubecode
    #uurl = 'plugin://plugin.video.youtube/v/%s' % youtubecode
    #	print uurl
    xbmc.executebuiltin("xbmc.PlayMedia("+uurl+")")

    return
#end function


def PlayLiveLink ( url ): 
#	url = tabURL.replace('%s',channelName);
	req = urllib2.Request(url)
	req.add_header('User-Agent', 'Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B314 Safari/531.21.10')
	response = urllib2.urlopen(req)
	link=response.read()
	response.close()
#	print link
	print url

#	match =re.findall('<script id.+\s+src="(.*)">',link,  re.IGNORECASE)

	match =re.findall('"http.*(ebound).*?\?site=(.*?)"',link,  re.IGNORECASE)[0]


	print match
	cName=match[1]
	newURL='http://www.eboundservices.com/iframe/newads/iframe.php?stream='+ match[1]+'&width=undefined&height=undefined&clip=' + match[1]
	name=match[1];
	print newURL

	
	req = urllib2.Request(newURL)
	req.add_header('User-Agent', 'Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B314 Safari/531.21.10')
	response = urllib2.urlopen(req)
	link=response.read()
	response.close()
	
	
#	match =re.findall('<iframe.+src=\'(.*)\' frame',link,  re.IGNORECASE)
#	print match
#	req = urllib2.Request(match[0])
#	req.add_header('User-Agent', 'Mozilla/5.0(iPad; U; CPU iPhone OS 3_2 like Mac OS X; en-us) AppleWebKit/531.21.10 (KHTML, like Gecko) Version/4.0.4 Mobile/7B314 Safari/531.21.10')
#	response = urllib2.urlopen(req)
#	link=response.read()
#	response.close()
	time = 2000  #in miliseconds
	defaultStreamType=0 #0 RTMP,1 HTTP
	defaultStreamType=selfAddon.getSetting( "DefaultStreamType" ) 
	print 'defaultStreamType',defaultStreamType
	if linkType=="HTTP" or (linkType=="" and defaultStreamType=="1"):
#	print link
		line1 = "Playing Http Stream"
		xbmc.executebuiltin('Notification(%s, %s, %d, %s)'%(__addonname__,line1, time, __icon__))
		
		match =re.findall('MM_openBrWindow\(\'(.*)\',\'ebound\'', link,  re.IGNORECASE)
			
	#	print url
	#	print match
		
		strval = match[0]
		
		#listitem = xbmcgui.ListItem(name)
		#listitem.setInfo('video', {'Title': name, 'Genre': 'Live TV'})
		#playlist = xbmc.PlayList( xbmc.PLAYLIST_VIDEO )
		#playlist.clear()
		#playlist.add (strval)
		
		#xbmc.Player().play(playlist)
		listitem = xbmcgui.ListItem( label = str(name), iconImage = "DefaultVideo.png", thumbnailImage = xbmc.getInfoImage( "ListItem.Thumb" ), path=strval )
		print "playing stream name: " + str(name) 
		listitem.setInfo( type="video", infoLabels={ "Title": name, "Path" : strval } )
		#listitem.setInfo( type="video", infoLabels={ "Title": name, "Plot" : name, "TVShowTitle": name } )
		xbmc.Player( xbmc.PLAYER_CORE_DVDPLAYER ).play( str(strval), listitem)
	else:
		line1 = "Playing RTMP Stream"
		xbmc.executebuiltin('Notification(%s, %s, %d, %s)'%(__addonname__,line1, time, __icon__))
		
		#print link
		match =re.findall("m3u8.*?=(.*)[=]','e", link)

		print url
		print match

		strval = match[0]

		#listitem = xbmcgui.ListItem(name)
		#listitem.setInfo('video', {'Title': name, 'Genre': 'Live TV'})
		#playlist = xbmc.PlayList( xbmc.PLAYLIST_VIDEO )
		#playlist.clear()
		#playlist.add (strval)

		playfile='rtmp://cdn.ebound.tv/tv?wmsAuthSign=/%s app=tv?wmsAuthSign=?%s swfurl=http://www.eboundservices.com/live/v6/player.swf?domain=&channel=%s&country=GB pageUrl=http://www.eboundservices.com/iframe/newads/iframe.php?stream=%s tcUrl=rtmp://cdn.ebound.tv/tv?wmsAuthSign=?%s live=true'	% (cName,strval,cName,cName,strval)
		#playfile='rtmp://cdn.ebound.tv/tv?wmsAuthSign=/humtv app=tv?wmsAuthSign=?%s swfurl=http://www.eboundservices.com/live/v6/player.swf?domain=&channel=humtv&country=GB pageUrl=http://www.eboundservices.com/iframe/newads/iframe.php?stream=humtv tcUrl=rtmp://cdn.ebound.tv/tv?wmsAuthSign=?%s live=true'	% (strval,strval)

		print playfile
		#xbmc.Player().play(playlist)
		listitem = xbmcgui.ListItem( label = str(name), iconImage = "DefaultVideo.png", thumbnailImage = xbmc.getInfoImage( "ListItem.Thumb" ) )
		print "playing stream name: " + str(name) 
		#listitem.setInfo( type="video", infoLabels={ "Title": name, "Path" : playfile } )
		#listitem.setInfo( type="video", infoLabels={ "Title": name, "Plot" : name, "TVShowTitle": name } )
		xbmc.Player( xbmc.PLAYER_CORE_AUTO ).play( playfile, listitem)
	
	
	return
#end function

	
#print "i am here"
params=get_params()
url=None
name=None
mode=None
linkType=None

try:
	url=urllib.unquote_plus(params["url"])
except:
	pass
try:
	name=urllib.unquote_plus(params["name"])
except:
	pass
try:
	mode=int(params["mode"])
except:
	pass


args = cgi.parse_qs(sys.argv[2][1:])
linkType=''
try:
	linkType=args.get('linkType', '')[0]
except:
	pass


print 	mode

try:
	if mode==None or url==None or len(url)<1:
		print "InAddTypes"
		Addtypes()

	elif mode==2:
		print "Ent (mode,name,url) is ",(mode,name,url)
		AddTVChannels(url)

	elif mode==3:
		print "Ent (mode,name,url) is ",(mode,name,url)
		AddSeries(url)

	elif mode==4:
		print "Ent (mode,name,url) is ",(mode,name,url)
		AddEnteries(url)

	elif mode==5:
		print "Play (mode,name,url is ",(mode,name,url)
		PlayShowLink(url)
except:
	print 'somethingwrong'
xbmcplugin.endOfDirectory(int(sys.argv[1]))


		
