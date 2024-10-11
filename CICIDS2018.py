# -*- coding: utf-8 -*-

!pip install preprocessing

import numpy as np
import pandas as pd
import os
import sklearn

#import_data
df_dataset = pd.read_csv('/content/cleaned_ids2018_sampled.csv')
df_dataset

#df_dataset.info()

df_dataset.dropna(inplace=True)
df_dataset

# replace + and - infinity with NaN

df_dataset.replace([np.inf, -np.inf], np.nan, inplace=True)

# drop missing values

df_dataset.dropna(inplace=True)

# check the number of duplication row
print(df_dataset.duplicated().sum())

df_dataset.shape

df_dataset.drop_duplicates(inplace = True)


print(df_dataset.duplicated().sum())

df_dataset.shape

#Implementing binary classification
df_dataset["Label"].value_counts()

old_value=1
new_v = 0
df_dataset['Label'] = df_dataset['Label'].replace(old_value, new_v)

for i in range(2, 12):
    old_value = i
    new_value = 1
    df_dataset['Label'] = df_dataset['Label'].replace(old_value, new_value)

df_dataset["Label"].value_counts()

#Balancing the data (Undersampling)

import matplotlib.pyplot as plt
import joblib
import sklearn
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.utils import class_weight

RANDOM_STATE_SEED = 12

from plotly.offline import init_notebook_mode, iplot, plot
import plotly as py
import plotly.express as px
init_notebook_mode(connected=True)
import plotly.graph_objs as go

df = df_dataset
fig = go.Figure(data=[
    go.Bar(name='Benign',
           y=df["Label"].value_counts().values[0:1],
           x=['Benign'],
           text = df["Label"].value_counts()[0:1],
           orientation='h',
           textposition='outside',),

    go.Bar(name='Malicious',
           y=df["Label"].value_counts().values[1:2],
           x=['Malicious'],
           text = df["Label"].value_counts()[1:2],
           orientation='h',
           textposition='outside',)
])
# Change the bar mode
fig.update_layout(
                  width=800,
                  height=600,
                  title=f'Class Distribution',
                  yaxis_title='Number of attacks',
                  xaxis_title='Attack Name',)
iplot(fig)

#creating new data frame df_equal based on the old data frame and select first 255349 rows for df1 if the column is o and df2 for column 1
df1 = df[df["Label"] == 0][:255349]
df2 = df[df["Label"] == 1][:255349]
df_equal = pd.concat([ df1,df2], axis =0)
df_equal

import seaborn as sns
import matplotlib.pyplot as plt

# Replace this with your actual data

# Create a figure with subplots
fig, axes = plt.subplots(nrows=1, ncols=2, figsize=(5, 6))

# Plot for Benign group
sns.barplot(x=['Benign'], y=df_equal["Label"].value_counts().values[0:1], ax=axes[0])
axes[0].set_title("Benign")

# Plot for Malicious group
sns.barplot(x=['Malicious'], y=df_equal["Label"].value_counts().values[1:2], ax=axes[1])
axes[1].set_title("Malicious")

# Adjust layout
plt.tight_layout()

# Show the plots
plt.show()

#creating test and train

train, test = train_test_split(df_equal, test_size=0.2)
test

train
train.info()

#feature scaling

min_max_scaler = MinMaxScaler().fit(train[['Flow Duration', 'Tot Fwd Pkts',
       'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
       'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
       'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
       'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
       'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot',
       'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
       'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
       'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
       'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s',
       'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean',
       'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt',
       'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
       'CWE Flag Count', 'ECE Flag Cnt', 'Pkt Size Avg',
       'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
       'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
       'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
       'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
       'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts',
       'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
       'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']])

numerical_columns = ['Flow Duration', 'Tot Fwd Pkts',
       'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
       'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
       'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
       'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
       'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot',
       'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
       'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
       'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
       'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s',
       'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean',
       'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt',
       'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
       'CWE Flag Count', 'ECE Flag Cnt', 'Pkt Size Avg',
       'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
       'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
       'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
       'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
       'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts',
       'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
       'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']

train[numerical_columns] = min_max_scaler.transform(train[numerical_columns])
train

train.drop(['Unnamed: 0'], axis=1,inplace=True)
test.drop(['Unnamed: 0'],axis=1,inplace=True)

test[numerical_columns] = min_max_scaler.transform(test[numerical_columns])
test

print("Full dataset:\n")
print("Benign: " + str(df_equal["Label"].value_counts()[[0]].sum()))
print("Malicious: " + str(df_equal["Label"].value_counts()[[1]].sum()))
print("---------------")

print("Training set:\n")
print("Benign: " + str(train["Label"].value_counts()[[0]].sum()))
print("Malicious: " + str(train["Label"].value_counts()[[1]].sum()))
print("---------------")

print("Test set:\n")
print("Benign: " + str(test["Label"].value_counts()[[0]].sum()))
print("Malicious: " + str(test["Label"].value_counts()[[1]].sum()))

#Creating X, Y variables
y_train = np.array(train.pop("Label"))# pop removes "Label" from the dataframe
X_train = train.values

y_test = np.array(test.pop("Label")) # pop removes "Label" from the dataframe
X_test = test.values

#DecisionTree
from sklearn.tree  import DecisionTreeClassifier
from sklearn.model_selection import RandomizedSearchCV


dt = DecisionTreeClassifier(criterion = 'entropy', max_depth=5)

parameters = {'max_depth': [2, 4, 7, 10], 'min_samples_split': [2, 3, 5], 'min_samples_leaf': [1, 2, 3, 5], 'criterion': ['gini', 'entropy']}

random_search = RandomizedSearchCV(dt, param_distributions=parameters, n_iter=10, cv=5, n_jobs=-1)
random_search.fit(X_train, y_train)
best_accuracy = random_search.best_score_
best_parameters = random_search.best_params_

print("Best Accuracy: {:.2f} %".format(best_accuracy*100))
print("Best Parameters:", best_parameters)


from sklearn import metrics
best_dt = DecisionTreeClassifier(**random_search.best_params_)
best_dt.fit(X_train,y_train)

# Predicting Train & Test Results
y_dt = best_dt.predict(X_train)
y_pred_dt = best_dt.predict(X_test)

# Accuracy
print("Accuracy on Training set: ",metrics.accuracy_score(y_train, y_dt))
print("Accuracy on Testing set: ",metrics.accuracy_score(y_test, y_pred_dt))
