#!/usr/bin/env python
# coding: utf-8

# In[9]:
import joblib
import numpy as np
import pandas as pd
import f_extraction
import math
clf = joblib.load('rf1.pkl')
def check(url):
    features_test = f_extraction.main(url)
    f=pd.DataFrame(features_test)
    q=f.T
    if math.isnan(q[9]):
        q[9]=0
    if math.isnan(q[13])or math.isnan(q[14]):
        q[13]=0
        q[14]=0
    if math.isnan(q[15]):
        q[15]=0
    pred = clf.predict(q)
    
    return pred[0]
    

