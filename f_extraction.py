#!/usr/bin/env python
# coding: utf-8

# In[1]:


import regex as re   
from tldextract import extract
import ssl
import socket
from bs4 import BeautifulSoup
import urllib.request
import whois
import datetime
from urllib.parse import urlparse,urlencode


# In[2]:



def url_having_ip(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return -1
    else:
        # print 'No matching pattern found'
        return 1


   


# In[3]:


def url_length(url):
    length=len(url)
    if(length<54):
        return 1
    elif(54<=length<=75):
        return 0
    else:
        return -1


# In[4]:


def url_short(url):
    #ongoing
     match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
     if match:
        return -1
     else:
        return 1


    


# In[5]:


def having_at_symbol(url):
    match = re.search('@', url)
    if match:
        return -1
    else:
        return 1
 


# In[6]:


def doubleSlash(url):
    #ongoing
    
    try:
        list = [x.start(0) for x in re.finditer('//', url)]
        if list[len(list) - 1] > 6:
            return -1
        else:
            return 1
    except:
        return 0


     


# In[7]:


def prefix_suffix(url):
    subDomain, domain, suffix = extract(url)
    
    if(domain.count('-')):
        return -1
    else:
        return 1



# In[8]:


def sub_domain(url):
    # Here, instead of greater than 1 we will take greater than 3 since the greater than 1 conition is when www and
    # country domain dots are skipped
    # Accordingly other dots will increase by 1
    if url_having_ip(url) == -1:
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
            url)
        pos = match.end(0)
        url = url[pos:]
    list = [x.start(0) for x in re.finditer('\.', url)]
    if len(list) <= 3:
        return 1
    elif len(list) == 4:
        return 0
    else:
        return -1
    
    



# In[9]:


def SSLfinal_State(url):
    try:
#check wheather contains https       
        if(re.search('^https',url)):
            usehttps = 1
        else:
            usehttps = 0
        #print(usehttps)
#getting the certificate issuer to later compare with trusted issuer 
        #getting host name
        subDomain, domain, suffix = extract(url)
        host_name = domain + "." + suffix
        context = ssl.create_default_context()
        sct = context.wrap_socket(socket.socket(), server_hostname = host_name)
        sct.connect((host_name, 443))
        certificate = sct.getpeercert()
        issuer = dict(x[0] for x in certificate['issuer'])
        certificate_Auth = str(issuer['commonName'])
        certificate_Auth = certificate_Auth.split()
        if(certificate_Auth[0] == "Network" or certificate_Auth == "Deutsche"):
            certificate_Auth = certificate_Auth[0] + " " + certificate_Auth[1]
        else:
            certificate_Auth = certificate_Auth[0] 
        trusted_Auth = ['Comodo','Symantec','GoDaddy','GlobalSign','DigiCert','StartCom','Entrust','Verizon','Trustwave','Unizeto','Buypass','QuoVadis','Deutsche Telekom','Network Solutions','SwissSign','IdenTrust','Secom','TWCA','GeoTrust','Thawte','Doster','VeriSign']        
#getting age of certificate
        startingDate = str(certificate['notBefore'])
        endingDate = str(certificate['notAfter'])
        startingYear = int(startingDate.split()[3])
        endingYear = int(endingDate.split()[3])
        Age_of_certificate = endingYear-startingYear
        
#checking final conditions
        if((usehttps==1) and (certificate_Auth in trusted_Auth) and (Age_of_certificate>=1) ):
            return 1 #legitimate
        elif((usehttps==1) and (certificate_Auth not in trusted_Auth)):
            return 0 #suspicious
        else:
            return -1 #phishing
        
    except Exception as e:
        
        return 0  
    
    



# In[10]:


def domain_registration(url):
   
    try:
    
        hostname = url
        h = [(x.start(0), x.end(0)) for x in re.finditer('https://|http://|www.|https://www.|http://www.', hostname)]
        z = int(len(h))
        if z != 0:
                y = h[0][1]
                hostname = hostname[y:]
                h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
                z = int(len(h))
                if z != 0:
                    hostname = hostname[:h[0][0]]
        domain = whois.whois(hostname)
    
        
        expiration_date = domain.expiration_date
        a=expiration_date.year
        b=expiration_date.day
        c=expiration_date.month
        exp=datetime.date(a,c,b)
        registration_length = 0
        today=datetime.datetime.now().date()
    # Some domains do not have expiration dates. The application should not raise an error if this is the case.
        if expiration_date:
            registration_length = abs((exp - today).days)
        if registration_length / 365 <= 1:
            return -1
        else:
            return 1
    except:
        return 0



# In[11]:


def favicon(url):
    try:
        subDomain, domain, suffix = extract(url)
        websiteDomain = domain
        
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        for head in soup.find_all('head'):
            
            for head.link in soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                if url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                    q=0
                else:
                    q=1
                    return -1
                    break
            if q==0:
                return 1
    except:
        return -1

def port(url):
    #ongoing
    return 0


# In[12]:


def https_token(url):
    match = re.search('https://|http://', url)
    if match.start(0) == 0:
        url = url[match.end(0):]
    match = re.search('http|https', url)
    if match:
        return -1
    else:
        return 1


# In[13]:


def request_url(url):
    try:
        subDomain, domain, suffix = extract(url)
        websiteDomain = domain
        
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        imgs = soup.findAll('img', src=True)
        total = len(imgs)
        
        linked_to_same = 0
        avg =0
        for image in imgs:
            subDomain, domain, suffix = extract(image['src'])
            imageDomain = domain
            if(websiteDomain==imageDomain or imageDomain==''):
                linked_to_same = linked_to_same + 1
        vids = soup.findAll('video', src=True)
        total = total + len(vids)
        
        for video in vids:
            subDomain, domain, suffix = extract(video['src'])
            vidDomain = domain
            if(websiteDomain==vidDomain or vidDomain==''):
                linked_to_same = linked_to_same + 1
        linked_outside = total-linked_to_same
        if(total!=0):
            avg = linked_outside/total
            
        if(avg<0.22):
            return 1
        elif(0.22<=avg<=0.61):
            return 0
        else:
            return -1
    except:
        return -1



# In[14]:


def url_of_anchor(url):
    try:
        subDomain, domain, suffix = extract(url)
        websiteDomain = domain
        
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        z=soup.find_all('a')
        total = len(z)
        #print(total)
        linked_to_same = 0
        linked_outside=0
        avg = 0
        for link in soup.find_all('a'):
            a=link.get('href')
            subDomain, domain, suffix = extract(a)
            anchorDomain = domain
            if(websiteDomain==anchorDomain or anchorDomain==''):
                linked_to_same = linked_to_same + 1
        linked_outside = total-linked_to_same
        #print(linked_outside)
        if(total!=0):
            avg = linked_outside/total
           # print(avg)
            
        if(avg<0.31):
           #print(avg)
            return 1
        elif(0.31<=avg<=0.67):
            return 0
        else:
            return -1
    except:
        return -1


# In[ ]:





# In[52]:





# In[ ]:





# In[15]:


def Links_in_tags(url):
    try:
        subDomain, domain, suffix = extract(url)
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        
        i = 0
        success = 0
        for link in soup.find_all('link', href=True):
            #print(link.get('href'))
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            #print(dots)
            if url in link['href'] or domain in link['href'] or len(dots) == 1:
                success = success + 1
            i = i + 1
        for script in soup.find_all('script', src=True):
            #print(script.get('src'))
            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
            #print(dots)
            if url in script['src'] or domain in script['src'] or len(dots) == 1:
                success = success + 1
            i = i + 1
        for meta in soup.find_all('meta', content=True):
            #print(meta.get('content'))
            dots = [x.start(0) for x in re.finditer('\.', meta['content'])]
            #print(dots)
            if url in meta['content'] or domain in meta['content'] or len(dots) == 1:
                success = success + 1
            i = i + 1
        
        if(i!=0):
            avg = success/i
            #print(avg)

        if(avg<0.17):
            return 1
        elif(0.17<=avg<=0.81):
            return 0
        else:
            return -1        
    except:        
        return -1


# In[16]:


def sfh(url):
    try:
        subDomain, domain, suffix = extract(url)
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        for form in soup.find_all('form', action=True):
        #print(form)
            if form['action'] == "" or form['action'] == "about:blank":
                return -1
            elif url not in form['action'] and domain not in form['action']:
                return 0
            else:
                return 1
    except:
        return -1
    
    



# In[18]:


def email_submit(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        for form in soup.find_all('form', action=True):
            if "mailto:" in form['action']:
                return -1
            else:
                return 1
    except:
        return -1


# In[19]:


def abnormal_url(url):
    hostname = url
    h = [(x.start(0), x.end(0)) for x in re.finditer('https://|http://|www.|https://www.|http://www.', hostname)]
    z = int(len(h))
    if z != 0:
        y = h[0][1]
        hostname = hostname[y:]
        h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
        z = int(len(h))
        if z != 0:
            hostname = hostname[:h[0][0]]
    match = re.search(hostname, url)
    if match:
        return 1
    else:
        return -1

def redirect(url):
    #ongoing
     #If the url has symbol(//) after protocol then such URL is to be classified as phishing """
        if "//" in urlparse(url).path:
            return 1            # phishing
        else:
            return 0            # legitimate
    #return 0


def on_mouseover(url):
    #ongoing
    return 0

def rightClick(url):
    #ongoing
    return 0

def popup(url):
    #ongoing
    return 0

def iframe(url):
    #ongoing
    return 0


# In[20]:



def age_of_domain(url):
   try:
       hostname = url
       h = [(x.start(0), x.end(0)) for x in re.finditer('https://|http://|www.|https://www.|http://www.', hostname)]
       z = int(len(h))
       if z != 0:
               y = h[0][1]
               hostname = hostname[y:]
               h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
               z = int(len(h))
               if z != 0:
                   hostname = hostname[:h[0][0]]
       domain = whois.whois(hostname)
    
   
       creation_date = domain.creation_date
       expiration_date = domain.expiration_date
       if ((expiration_date is None) or (creation_date is None)):
           return 1
       elif ((type(expiration_date) is list) or (type(creation_date) is list)):
           return 0
       else:
           ageofdomain = abs((expiration_date - creation_date).days)
       if ((ageofdomain/30) < 6):
           return -1
       else:
           return 1
   except:
       return -1


# In[21]:


def dns(url):
    #ongoing
    return 0

def web_traffic(url):
    try:
        
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        rank= int(rank)
        if (rank<100000):
            return 1
        else:
            return 0
    except:
        return -1
    

def page_rank(url):
    #ongoing
    return 0

def google_index(url):
    site = re.search(url, 5)
    if site:
        return 1
    else:
        return -1


def links_pointing(url):
    #ongoing
    return 0

def statistical(url):
    #ongoing
    return 0


# In[49]:





# In[ ]:





# In[25]:




def main(url):
    import pandas as pd


    
    
    check = [url_having_ip(url),url_length(url),url_short(url),having_at_symbol(url),doubleSlash(url),prefix_suffix(url),sub_domain(url),SSLfinal_State(url),domain_registration(url),favicon(url),https_token(url),request_url(url),url_of_anchor(url),Links_in_tags(url),sfh(url),email_submit(url),abnormal_url(url),redirect(url),age_of_domain(url),web_traffic(url)]
    check1=pd.DataFrame(check)
    
     
    return check1
