# Machine Learning Model - Training and Evaluation (CRISP-DM)
<p align="justify">
This is a machine learning model training project, following the 6 step CRISP-DM method. The business purpose of the model is to analyse user provided URL's and be able to provide a direct assessment, indentifying if they should be seen as potentially malicious (phishing, credential stealer...). 

Regular platforms for URL check's usually rely on previously available reports to assess the URL, while the proposed approach of using a ML model is able to provide an assessment based on paterns identified on the URL and webpage content. 

The model was trained using a tabular dataset available in https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning.

Guidance notes and context are provided directly on the jupyter noteboook files, along with the code. 

Different models were trained and made available [here](models/).
The features used for these models can be checked in the [training](model_train.ipynb) or [deployment](deployment.ipynb) jupyter notebooks. These include features that require the URL to be fetched (HTTP GET), so have that in consideration in case you want to deploy. 
In case the URL is not reachable or down, the code made available in [basic webapp](app.py) and [deployment file](deployment.ipynb) will still provide a model analysis based only on the passive features.



</p>
