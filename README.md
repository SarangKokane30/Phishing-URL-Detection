
# Phishing URL Detection 
<img width="1912" height="920" alt="image" src="https://github.com/user-attachments/assets/00dc8815-3f79-4b7d-ab79-a14422401585" />
<img width="1889" height="924" alt="image" src="https://github.com/user-attachments/assets/80b35404-f5d1-4cb6-ad3b-cc9925ad805b" />


## Table of Contents
- [Introduction](#introduction)
- [Installation](#installation)
- [Directory Tree](#directory-tree)
- [Result](#result)
- [Conclusion](#conclusion)


## Introduction

With the rapid growth of the internet, phishing has emerged as one of the most common cyber threats. Attackers often trick users into revealing sensitive data such as usernames, passwords, or financial details through fake websites.  

Traditional rule-based filters struggle against evolving phishing tactics, which is why **Machine Learning (ML)** provides a strong alternative. By learning the underlying patterns in malicious URLs, ML models can automatically flag phishing attempts with high accuracy.  

👉 This project applies multiple ML algorithms to classify URLs as *legitimate* or *phishing*, and compares their performance.   To see project click [here]("https://github.com/SarangKokane30/Phishing-URL-Detection").


## Installation
The project is implemented in **Python 3.6+**. Make sure you have Python installed (download [here](https://www.python.org/downloads/)) and then install all required libraries with:  

```bash
pip install -r requirements.txt
```
## Directory Tree 
```
├── pickle
│   ├── model.pkl
├── static
│   ├── styles.css
├── templates
│   ├── index.html
├── Phishing URL Detection.ipynb
├── Procfile
├── README.md
├── app.py
├── feature.py
├── phishing.csv
├── requirements.txt


```

## Technologies Used

![](https://forthebadge.com/images/badges/made-with-python.svg)

[<img target="_blank" src="https://upload.wikimedia.org/wikipedia/commons/3/31/NumPy_logo_2020.svg" width=200>](https://numpy.org/doc/) [<img target="_blank" src="https://upload.wikimedia.org/wikipedia/commons/e/ed/Pandas_logo.svg" width=200>](https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.html)
[<img target="_blank" src="https://upload.wikimedia.org/wikipedia/commons/8/84/Matplotlib_icon.svg" width=100>](https://matplotlib.org/)
[<img target="_blank" src="https://scikit-learn.org/stable/_static/scikit-learn-logo-small.png" width=200>](https://scikit-learn.org/stable/) 
[<img target="_blank" src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcScq-xocLctL07Jy0tpR_p9w0Q42_rK1aAkNfW6sm3ucjFKWML39aaJPgdhadyCnEiK7vw&usqp=CAU" width=200>](https://flask.palletsprojects.com/en/2.0.x/) 

## Result

Accuracy of various model used for URL detection
<br>

<br>

||ML Model|	Accuracy|  	f1_score|	Recall|	Precision|
|---|---|---|---|---|---|
0|	Gradient Boosting Classifier|	0.974|	0.977|	0.994|	0.986|
1|	Multi-layer Perceptron|	        0.969|	0.973|	0.995|	0.981|
2|	Random Forest|	                0.967|	0.971|	0.993|	0.990|
3|	Support Vector Machine|	        0.964|	0.968|	0.980|	0.965|
4|	Decision Tree|      	        0.960|	0.964|	0.991|	0.993|
5|	K-Nearest Neighbors|        	0.956|	0.961|	0.991|	0.989|
6|	Logistic Regression|        	0.934|	0.941|	0.943|	0.927|
7|	Naive Bayes Classifier|     	0.605|	0.454|	0.292|	0.997|

Feature importance for Phishing URL Detection 
<br><br>
![image](https://github.com/user-attachments/assets/7abb0090-30fe-4f10-a797-19f5e761ac7c)




## Conclusion
1. Gradient Boosting delivered the best accuracy (97.4%), making it the most reliable model in this project.
2. Features such as HTTPS presence, anchor tags, and website traffic had the most significant impact on predictions.
3. Ensemble methods (Gradient Boosting, CatBoost, XGBoost) outperformed simpler algorithms like Logistic Regression or Naïve Bayes.
4. Building this project gave deeper understanding of feature engineering, model tuning, and how small changes can shift performance.
