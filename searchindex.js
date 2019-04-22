Search.setIndex({docnames:["api/arxiv.vault/arxiv.vault","api/arxiv.vault/arxiv.vault.adapter","api/arxiv.vault/arxiv.vault.core","api/arxiv.vault/arxiv.vault.hvac_extensions","api/arxiv.vault/arxiv.vault.hvac_extensions.api","api/arxiv.vault/arxiv.vault.hvac_extensions.api.secrets_engines","api/arxiv.vault/arxiv.vault.hvac_extensions.api.secrets_engines.mysql","api/arxiv.vault/arxiv.vault.hvac_extensions.v1","api/arxiv.vault/arxiv.vault.manager","api/arxiv.vault/arxiv.vault.middleware","api/arxiv.vault/arxiv.vault.tests","api/arxiv.vault/arxiv.vault.tests.test_manager","api/arxiv.vault/arxiv.vault.tests.test_middleware","api/arxiv.vault/modules","architecture","index"],envversion:{"sphinx.domains.c":1,"sphinx.domains.changeset":1,"sphinx.domains.cpp":1,"sphinx.domains.javascript":1,"sphinx.domains.math":2,"sphinx.domains.python":1,"sphinx.domains.rst":1,"sphinx.domains.std":1,"sphinx.ext.intersphinx":1,"sphinx.ext.todo":1,"sphinx.ext.viewcode":1,sphinx:56},filenames:["api/arxiv.vault/arxiv.vault.rst","api/arxiv.vault/arxiv.vault.adapter.rst","api/arxiv.vault/arxiv.vault.core.rst","api/arxiv.vault/arxiv.vault.hvac_extensions.rst","api/arxiv.vault/arxiv.vault.hvac_extensions.api.rst","api/arxiv.vault/arxiv.vault.hvac_extensions.api.secrets_engines.rst","api/arxiv.vault/arxiv.vault.hvac_extensions.api.secrets_engines.mysql.rst","api/arxiv.vault/arxiv.vault.hvac_extensions.v1.rst","api/arxiv.vault/arxiv.vault.manager.rst","api/arxiv.vault/arxiv.vault.middleware.rst","api/arxiv.vault/arxiv.vault.tests.rst","api/arxiv.vault/arxiv.vault.tests.test_manager.rst","api/arxiv.vault/arxiv.vault.tests.test_middleware.rst","api/arxiv.vault/modules.rst","architecture.rst","index.rst"],objects:{"arxiv.vault":{adapter:[1,0,0,"-"],core:[2,0,0,"-"],hvac_extensions:[3,0,0,"-"],manager:[8,0,0,"-"],middleware:[9,0,0,"-"],tests:[10,0,0,"-"]},"arxiv.vault.adapter":{HostnameLiberalAdapter:[1,1,1,""],HostnameLiberalHTTPAdapter:[1,1,1,""]},"arxiv.vault.adapter.HostnameLiberalHTTPAdapter":{init_poolmanager:[1,2,1,""]},"arxiv.vault.core":{Secret:[2,1,1,""],Token:[2,1,1,""],Vault:[2,1,1,""]},"arxiv.vault.core.Secret":{expires:[2,3,1,""],is_expired:[2,2,1,""]},"arxiv.vault.core.Vault":{authenticate:[2,2,1,""],authenticated:[2,3,1,""],aws:[2,2,1,""],client:[2,3,1,""],generic:[2,2,1,""],kubernetes_mountpoint:[2,3,1,""],mysql:[2,2,1,""],renew:[2,2,1,""]},"arxiv.vault.hvac_extensions":{api:[4,0,0,"-"],v1:[7,0,0,"-"]},"arxiv.vault.hvac_extensions.api":{SecretsEngines:[4,1,1,""],secrets_engines:[5,0,0,"-"]},"arxiv.vault.hvac_extensions.api.SecretsEngines":{implemented_classes:[4,3,1,""],unimplemented_classes:[4,3,1,""]},"arxiv.vault.hvac_extensions.api.secrets_engines":{mysql:[6,0,0,"-"]},"arxiv.vault.hvac_extensions.api.secrets_engines.mysql":{MySql:[6,1,1,""]},"arxiv.vault.hvac_extensions.api.secrets_engines.mysql.MySql":{generate_credentials:[6,2,1,""],read_role:[6,2,1,""]},"arxiv.vault.hvac_extensions.v1":{Client:[7,1,1,""]},"arxiv.vault.manager":{AWSSecretRequest:[8,1,1,""],ConfigManager:[8,1,1,""],DatabaseSecretRequest:[8,1,1,""],GenericSecretRequest:[8,1,1,""],SecretRequest:[8,1,1,""],SecretsManager:[8,1,1,""]},"arxiv.vault.manager.AWSSecretRequest":{mount_point:[8,3,1,""],role:[8,3,1,""],slug:[8,3,1,""]},"arxiv.vault.manager.ConfigManager":{role:[8,3,1,""],token:[8,3,1,""],yield_secrets:[8,2,1,""]},"arxiv.vault.manager.DatabaseSecretRequest":{database:[8,3,1,""],engine:[8,3,1,""],host:[8,3,1,""],mount_point:[8,3,1,""],params:[8,3,1,""],port:[8,3,1,""],role:[8,3,1,""],slug:[8,3,1,""]},"arxiv.vault.manager.GenericSecretRequest":{key:[8,3,1,""],minimum_ttl:[8,3,1,""],mount_point:[8,3,1,""],path:[8,3,1,""],slug:[8,3,1,""]},"arxiv.vault.manager.SecretRequest":{factory:[8,4,1,""]},"arxiv.vault.manager.SecretsManager":{yield_secrets:[8,2,1,""]},"arxiv.vault.middleware":{VaultMiddleware:[9,1,1,""]},"arxiv.vault.tests":{test_manager:[11,0,0,"-"],test_middleware:[12,0,0,"-"]},"arxiv.vault.tests.test_manager":{TestGetSecrets:[11,1,1,""],TestGetSecretsNotAuthenticated:[11,1,1,""]},"arxiv.vault.tests.test_manager.TestGetSecrets":{setUp:[11,2,1,""],test_aws_request:[11,2,1,""],test_generic_request:[11,2,1,""],test_generic_request_nonrenewable:[11,2,1,""],test_generic_request_with_minimum_ttl:[11,2,1,""],test_mysql_credentials:[11,2,1,""]},"arxiv.vault.tests.test_manager.TestGetSecretsNotAuthenticated":{setUp:[11,2,1,""],test_generic_request:[11,2,1,""]},"arxiv.vault.tests.test_middleware":{TestMiddleware:[12,1,1,""],TestMiddlewareMisconfigured:[12,1,1,""]},"arxiv.vault.tests.test_middleware.TestMiddleware":{setUp:[12,2,1,""],test_request:[12,2,1,""]},"arxiv.vault.tests.test_middleware.TestMiddlewareMisconfigured":{test_init:[12,2,1,""]},arxiv:{vault:[0,0,0,"-"]}},objnames:{"0":["py","module","Python module"],"1":["py","class","Python class"],"2":["py","method","Python method"],"3":["py","attribute","Python attribute"],"4":["py","classmethod","Python class method"]},objtypes:{"0":"py:module","1":"py:class","2":"py:method","3":"py:attribute","4":"py:classmethod"},terms:{"case":[8,11,12],"class":[1,2,4,6,7,8,9,11,12],"default":[8,9,14],"new":6,"return":[2,6,8,14],"short":14,"true":[2,7],"var":8,AWS:[2,8,11,14],Aws:4,For:[8,14],The:[8,11,12,14],Used:2,Using:14,abl:14,about:8,access:8,account:2,adapt:[0,4,6,7,13],add:4,addit:[8,9,14],against:[2,8,9],alicloud:4,allow_redirect:7,along:14,ani:14,api:[0,2,3,14],app:[0,11,12,14],applic:[8,14],appropri:8,architectur:15,arg:1,arxiv:14,as_of:2,assert:1,attempt:8,auth:[2,8,9,14],authent:[2,8,9,11,14],automat:14,avail:8,aws:[2,4,8],awssecretrequest:8,azur:4,background:15,base:[1,2,4,6,7,8,9,11,12,14],been:8,befor:14,bit:14,block:1,bool:2,bound:14,call:8,can:14,cassandra:4,celeri:14,cert:[7,14],certif:14,check:2,classmethod:8,clearinghous:14,client:[1,2,7,14],cluster:2,complex:14,compon:15,config:[8,9,14],configmanag:[8,14],configur:[2,8,12,14],connect:[1,8,11],consid:14,constraint:14,consul:4,consum:14,contain:14,content:15,core:[0,8,13,14],creat:14,cred:6,credenti:[2,6,8,11,14],current:[2,14],daemon:14,data:8,databas:[2,4,6,8,14],databasesecretrequest:8,date:14,datetim:2,definit:6,depend:8,deploi:14,deploy:14,descript:8,design:14,desir:8,detail:14,dialect:8,disk:14,doc:[6,8],doe:14,domain:14,don:14,durat:14,dure:14,each:14,easier:14,either:14,elimin:14,emb:14,endpoint:[6,8,9,14],engin:[2,5,6,7,8,14],env:8,etc:14,everi:14,exampl:8,expand:[8,9],expir:[2,8,14],expiry_margin:8,express:[8,9],extend:[1,7],extens:[3,14],factori:8,fals:1,flask:[8,12,14],follow:14,form:8,frequent:8,fresh:14,from:[2,8,9,14],fulfil:[8,14],futur:14,gcp:4,gcpkm:4,gener:[2,6,8,11,14],generate_credenti:6,genericsecretrequest:8,get:[2,9],goal:[8,14],grab:11,handl:[8,14],has:8,hashicorp:14,have:[11,12,14],hold:14,host:[2,8],hostnam:[1,8,14],hostnameliberaladapt:1,hostnameliberalhttpadapt:1,how:[8,9],html:[6,8],http:[1,2,6,8,9,12,14],httpadapt:1,human:14,hvac:[1,2,3,4,6,7,14],hvac_extens:[0,13,14],iam:8,ident:4,ignor:1,implement:[5,6,14],implemented_class:4,includ:14,increas:14,increment:2,index:15,indic:2,inform:14,init_poolmanag:1,initi:1,insid:14,instanc:14,instanti:12,integr:[0,14],interact:14,intervent:14,is_expir:2,issu:2,iter:8,its:[8,14],itself:14,janki:14,keep:14,kei:[2,8,14],kill:14,kind:[8,14],kinesi:14,kube_token:[2,8,9,14],kubernet:[2,8,9,14],kubernetes_mountpoint:2,kwarg:1,leas:[2,14],lease_dur:2,lease_id:2,lifetim:14,lightweight:14,like:8,live:14,load:14,mai:14,make:14,manag:[0,11,13,14],manual:14,map:[6,14],maria:6,mariadb:6,max_retri:1,maxsiz:1,method:[2,6,8,9,14],methodnam:[11,12],middlewar:[0,12,13,14],middlwar:12,mind:14,minimum:11,minimum_ttl:8,mock_secretsmanag:12,modul:[0,3,4,5,10,13,15],mongodb:4,monitor:14,more:8,mount:[2,8],mount_point:[2,6,8],mssql:4,much:14,must:14,mysql:[0,2,3,4,5,8,11,14],mysqldb:8,name:[2,6,8,14],namespac:[7,14],need:14,nice:14,nomad:4,none:[2,7,8],number:[8,14],object:[2,8,9],obtain:[2,8,14],one:8,onli:8,oper:14,option:[8,9],orchestr:14,org:8,other:14,our:14,outsid:14,overal:14,overrid:4,overview:15,packag:[13,15],page:15,paradigm:8,param:8,paramet:[2,8,9],part:[8,14],path:[2,8,14],pattern:14,period:14,pki:[4,14],plan:14,pod:14,point:8,polici:[2,8,14],pool_block:1,pool_connect:1,pool_maxs:1,poolmanag:1,popul:9,port:[2,8,14],postgresql:4,pre:[2,8],process:14,profil:14,project:14,protect:14,provid:[2,6,8,9,14],provis:14,proxi:7,python:[0,14],queri:6,rabbitmq:4,read_rol:6,readi:14,receiv:12,reduc:14,refer:6,refresh:14,regist:2,registri:4,renew:[2,8,11],repres:[2,8],request:[1,8,9,12,14],request_typ:8,requir:[8,11,15],resourc:14,respons:14,restart:14,retriev:[2,8,14],revok:14,role:[2,6,8,14],rotat:14,run:[8,14],runtest:[11,12],runtim:14,scheme:2,search:15,secret:[2,5,6,7,8,9,11,14],secretrequest:[8,14],secrets_engin:[0,3,4,14],secretsengin:4,secretsmanag:[8,9,11,14],secur:14,see:[8,9,14],self:14,sensit:[8,14],server:8,servic:2,serviceaccount:14,session:7,setup:[11,12],should:[8,9,14],sidecar:14,sign:14,simpl:2,slug:8,solut:15,some:8,sourc:[1,2,4,6,7,8,9,11,12],specif:14,sqlalchemi:8,ssh:4,str:[2,8],strategi:15,string:8,style:8,submodul:[4,13],subpackag:13,subsequ:14,support:[4,8,9,14],system:14,test:[0,13],test_aws_request:11,test_generic_request:11,test_generic_request_nonrenew:11,test_generic_request_with_minimum_ttl:11,test_init:12,test_manag:[0,10],test_middlewar:[0,10],test_mysql_credenti:11,test_request:12,testcas:[11,12],testgetsecret:11,testgetsecretsnotauthent:11,testmiddlewar:12,testmiddlewaremisconfigur:12,than:8,thei:14,them:14,therefor:14,thi:14,thing:[8,14],time:[8,14],timeout:7,todo:[8,9],tok:8,token:[2,7,8,14],ton:14,totp:4,transit:4,transpar:8,ttl:11,tupl:8,type:[2,6,8,14],typic:8,unimplemented_class:4,unittest:[11,12],updat:14,uri:[8,14],url:[7,8],usag:[],use:[1,7,8,11,12,14],used:[8,9,14],uses:14,using:[2,14],valid:14,valu:[2,8,14],variabl:8,vault:[13,14],vault_api_bas:6,vault_host:[8,9,14],vault_port:[8,9,14],vault_request:[8,9,14],vault_rol:14,vault_schem:[8,9,14],vaultapibas:6,vaultmiddlewar:[9,14],vaultproject:6,verifi:[2,7],via:14,vt_co:6,wai:14,want:[8,14],when:8,where:[2,8],whether:2,which:[2,8,14],within:[2,8,14],without:[1,14],work:8,wsgi:14,wsgi_app:9,www:6,yet:8,yield:8,yield_secret:8},titles:["arxiv.vault package","arxiv.vault.adapter module","arxiv.vault.core module","arxiv.vault.hvac_extensions package","arxiv.vault.hvac_extensions.api package","arxiv.vault.hvac_extensions.api.secrets_engines package","arxiv.vault.hvac_extensions.api.secrets_engines.mysql module","arxiv.vault.hvac_extensions.v1 module","arxiv.vault.manager module","arxiv.vault.middleware module","arxiv.vault.tests package","arxiv.vault.tests.test_manager module","arxiv.vault.tests.test_middleware module","arxiv","Architectural overview","arXiv Vault Integration"],titleterms:{adapt:1,api:[4,5,6],architectur:14,arxiv:[0,1,2,3,4,5,6,7,8,9,10,11,12,13,15],background:14,compon:14,core:2,hvac_extens:[3,4,5,6,7],indic:15,integr:15,manag:8,middlewar:9,modul:[1,2,6,7,8,9,11,12],mysql:6,overview:14,packag:[0,3,4,5,10],requir:14,secrets_engin:[5,6],solut:14,strategi:14,submodul:[0,3,5,10],subpackag:[0,3,4],tabl:15,test:[10,11,12],test_manag:11,test_middlewar:12,vault:[0,1,2,3,4,5,6,7,8,9,10,11,12,15]}})