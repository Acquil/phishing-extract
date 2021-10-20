# -*- coding: utf-8 -*-

import pandas as pd
dataset_legit = pd.read_csv("legit_features.tsv",header=None,sep="\t")
dataset_phish = pd.read_csv("phish_features.tsv",header=None,sep="\t")
dataset = pd.concat([dataset_legit,dataset_phish])

display(dataset)

dataset = dataset.dropna()
dataset

# dataset = dataset.drop_duplicates().dropna()
# dataset

# drop asn and country code
dataset = dataset.drop([17,18,19,20,21,22,23,24,25],axis=1)

import numpy as np

dataset["label"] = np.where(dataset[26]=="Phishing", 1, 0)
dataset

dataset = dataset.sample(frac=1).reset_index(drop=True)
dataset

X = dataset.iloc[:, 1:24].values
y = dataset["label"].values

from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)

from sklearn.ensemble import RandomForestClassifier

clf = RandomForestClassifier(n_estimators=100, random_state=0)
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)

from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

print(confusion_matrix(y_test,y_pred))
print(classification_report(y_test,y_pred))
print("----------------------------------------------")
print("Accuracy - Random Forest")
print(accuracy_score(y_test, y_pred))

"""***Adaboost***"""

from sklearn.ensemble import  AdaBoostClassifier
adaboost_clf = AdaBoostClassifier(n_estimators=100)
adaboost_clf.fit(X_train, y_train)
adaboost_y_pred = clf.predict(X_test)

print(confusion_matrix(y_test,adaboost_y_pred))
print(classification_report(y_test,adaboost_y_pred))
print("----------------------------------------------")
print("Accuracy - Adaboost")
print(accuracy_score(y_test, adaboost_y_pred))

"""***SVM***"""

import matplotlib.pyplot as plt 
from sklearn import svm

C = 1.0  # SVM regularization parameter
 
# SVC with linear kernel
svc = svm.SVC(kernel='linear').fit(X, y)
# LinearSVC (linear kernel)
# lin_svc = svm.LinearSVC(C=C).fit(X, y)

svc_y_pred = svc.predict(X_test)
print(confusion_matrix(y_test,svc_y_pred))
print(classification_report(y_test,svc_y_pred))
print("----------------------------------------------")
print("Accuracy - SVM")
print(accuracy_score(y_test, svc_y_pred))

"""One hot encoding - asn and country

"""

dataset_legit = pd.read_csv("legit_features.tsv",header=None,sep="\t")
dataset_phish = pd.read_csv("phish_features_2.tsv",header=None,sep="\t")
dataset = pd.concat([dataset_legit,dataset_phish])
dataset = dataset.drop_duplicates()
dataset = dataset.dropna()

dataset = dataset.sample(frac=1).reset_index(drop=True)
dataset["label"] = np.where(dataset[26]=="Phishing", 1, 0)

df = dataset
df = df.drop([0,26], axis=1)
df_dummy = pd.get_dummies(df)

X = df_dummy.drop(['label'],axis=1).values
y = df_dummy['label'].values

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)

clf = RandomForestClassifier(n_estimators=100, random_state=0)
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)

print(confusion_matrix(y_test,y_pred))
print(classification_report(y_test,y_pred))
print("----------------------------------------------")
print("Accuracy - Random Forest")
print(accuracy_score(y_test, y_pred))

df

import numpy as np

from scipy.stats import uniform, randint

from sklearn.metrics import auc, accuracy_score, confusion_matrix, mean_squared_error
from sklearn.model_selection import cross_val_score, GridSearchCV, KFold, RandomizedSearchCV, train_test_split

import xgboost as xgb

xgb_model = xgb.XGBClassifier(objective="binary:logistic", random_state=42)
xgb_model.fit(X_train, y_train)
    
y_pred = xgb_model.predict(X_test)
print(accuracy_score(y_test, y_pred))

kfold = KFold(n_splits=10, shuffle=True, random_state=42)

scores = []

for train_index, test_index in kfold.split(X):   
    X_train, X_test = X[train_index], X[test_index]
    y_train, y_test = y[train_index], y[test_index]
    clf = RandomForestClassifier(n_estimators=200, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    # xgb_model = xgb.XGBClassifier(objective="binary:logistic")
    # xgb_model.fit(X_train, y_train)
    
    # y_pred = xgb_model.predict(X_test)
    # print()
    scores.append(accuracy_score(y_test, y_pred))

np.mean(scores)

scores

a=[0.9517336485421591,
0.950354609929078,
0.9495665878644602,
0.9493695823483057,
0.9509359605911331,
0.9493596059113301,
0.9460098522167487,
0.9495566502463054,
0.9521182266009852,
0.9448275862068966 ]
np.mean(a)

def display_scores(scores):
    print("Scores: {0}\nMean: {1:.3f}\nStd: {2:.3f}".format(scores, np.mean(scores), np.std(scores)))

display_scores(np.sqrt(scores))