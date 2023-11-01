# Cli, Labeler, Labtune
cluster qualification, labeling, label management, console ui

 - Cli: 클러스터, 레이블, Qualifier 정보를 확인하고, 수작업으로 Qualifier를 설정하는 프로그램
 - Labeler: REconverge가 생성한 클러스터에게 Label을 지정하고, Qualification을 수행하는 프로그램
 - Labtune: 레이블을 관리하는 프로그램

## Cli
-----
  - 콘솔 UI를 통해서 클러스터를 검색, Qualifer 설정, Auto qualification/labeling 결과 확인
  - 사용방법: cli \<model-name\> 
    - 프로그램을 실행해서 "/help" 명령으로 도움말 확인
  - 역할:
    - labeler가 auto qualification/labeling한 결과를 UI를 통해서 검증.
    - 수작업으로 cluster qualifier를 설정.
    - (TODO) 수작업으로 레이블 부여하거나 수정.
    - 수작업으로 설정한 label/qualifier와 자동 분류한 결과를 비교.

## Labeler
-----
  - Auto qualification/labeling program
  - 사용방법: labeler \<model-name\>
   - cluster qualification and labeling
   - cluster의 qualifier에 따른 label 매칭 결과를 이용해서 레이블 토큰들에 대한 enable/disable 자동화 작업

## Labtune
-----
  - Label tuner. A program to tune labels.
  - Usage: labtune [\<model-name\>]
    - use `/help` command to see help message.
  - Purpose:
    - Json 형식의 Threat description 파일을 읽어서 Label을 DB 등록/관리한다.
    - labeler의 실행 결과로부터 레이블 혹은 레이블의 토큰/키워드 등의 사용 통계를 확인하고, 레이블을 튜닝하도록 지원한다.
  - Threat description. (= Label or threat Label)
    - Json file to describe threats.
    - Fields of this file: label name, description, references, samples, keywords, signature
  - Dictionary
    - 프로그램이 threat description의 samples에서 추출한 토큰들, 사용자가 입력한 토큰들, 프로그램이 REconverge의 Benign/Suspicious 클러스터에서 추출한 토큰들로 구성된 사전
    - The disabled tokens of labels consists of dictionary (currently).
  - Token, keywords, signature, dictionary
    - Token: Program extract it from the samples of threat description. User can only enable/disable tokens of labels.
    - Keywords: 샘플에서 추출한 단어 혹은 단어들 혹은 문자열로 구성. Exact matching으로 활용됨. 사용자가 직접 입력/수정. 이후 프로그램이 수집하는 것으로 바뀔 수 있음.
    - Signature: Regular expressions. (currently) Signatures read from threat descriptions.
    - Dictionary: Disabled tokens, and tokens collected from the benign clusters.

### Labtune commands
  - `/add keywords|signature <value>`<br>
    This command is to add keyword or regex signature And allowed only in label.<br>
    - Example:
    ```
    Labels [2]# /label #100054
    Labels (Label #100054) /add keywords SSL_CLIENT_VERIFY: SUCCESS,?action=file_download
    Keywords "SSL_CLIENT_VERIFY: SUCCESS,?action=file_download" added.

    Labels (Label #100054) 
    ...
    Keywords:
      [18]: ["SSL_CLIENT_VERIFY: SUCCESS", "?action=file_download"]
      [19]: ["application/json"]
      [20]: ["site_name "]
      [38]: ["SSL_CLIENT_VERIFY: SUCCESS", "?action=file_download"]
    ...
    ```
    - Comma(,) is delimiter. If you want to enter more than one keyword, use commna(,) without space before and after comma.<br>
    - The space character would be treated as part of keywords.<br>
    - `/save` command should be run after add or remove to save changes.
  - `/remove keywords|signature <pattern-no>`<br>
    This command is allowed only in label.<br>
    - Example: `/remove keywords 38`<br>
    - `pattern-no` is the leading number of keywords. Whenever run this `/remove keywords|signature` command runs, the `pattern-no` will be changed. Thus you should check it before run this command.

  - `/enable <token-list>`, `/disable <token-list>`

### Threat Description
-----
 - Json syntax. => Should support STIX
 - `Name`: Unique key. Duplicate not allowed.
 - `References`: Reference sites and CVE codes, etc. (Multiple)
 - `Samples`: Sample messages. As many as possible.
 - `Keywords`: Uniquly identifiable statement list extracted from the samples.
   - Not regular expression.
   - Tokens are generate automatically and used automatically also and user cannot control tokens-related things but it's possible that user can add/remove keywords for labels.
   - In the next example, the 3 words - "scripts", "setup.php", "ZmEu" - are matched orderly or 1 word - "ZmEu" - matched, then the label - "Web Vulnerability Scanner(Zgrab) - Type IV" - will be allocated to the target.
 - `Signature`: regular expressions.


#### 예제:
```
{
	"Name": "Web Vulnerability Scanner(Zgrab) - Type IV",
	"Description": "ZmEu is a computer vulnerability scanner which searches for web servers that are open to attack through the phpMyAdmin program,\n It also attempts to...",
	"References": ["CVE-001010", "http://www.example.com"],
	"Samples": [
		"GET /w00tw00t.at.blackhats.romanian.anti-sec:) HTTP/1.1 69.55.233.22 ZmEu",
		"GET /scripts/setup.php HTTP/1.1 69.55.233.22 ZmEu",
		"GET /w00tw00t.at.blackhats.romanian.anti-sec:) HTTP/1.1 69.55.233.23 ZmEu",
		"GET /phpMyAdmin-2.5.6/scripts/setup.php HTTP/1.1 69.55.233.22 ZmEu"],
	"Keywords": [["scripts", "setup.php", "ZmEu"], ["ZmEu"]],
	"Signature": ["scripts.+setup\\.php.+ZmEu"]
}
```

### Cli commands
-----
 - /load [force] \<filename\>
    - load Threat Descriptions and convert it to Label and save to DB.
    - 같은 이름의 Label을 덮어쓰려면 force 옵션을 사용해야한다. (not yet implemented)
    - ex) /load samples/w*.json
 - /export [<label-id> ...] | [with <desc>]
    - export label to json file or all labels to threat db file with description.
    - ex) /export 123456 654321 453521
    - ex) /export with collected from JB bank web analysis log
 - /remove label \<label-id\> \<label-id\> ...
    - remove Labels. This work would not applied to DB before executing `save` command.
 - /save
    - save all modified things to database: remove labels and all changes of tokens, keywords, signature
 - /disable \<token\> \<token\> ...
    - disable tokens of the Label in the label mode or all Labels.
    - User should run `save` command to apply the changes to DB.
 - /enable \<token\> \<token\> ...
    - enable tokens of the Label in the label mode or all Labels.
    - User should run `save` command to apply the changes to DB.
 - \#\<label-id\>
    - begin label mode with the specified label.
    - User can see the detail information of the label and can manage token, keywords, signature.
    - The changes for token, keywords, signature in the label mode applied only to the label.
    - "/x" : Exit from the label mode
 - \<page-no\>
    - jump to the page number.


## TODO
Label: import -> not to save directly
  - Not yet implemented
    - /add keyword \<keyword\>
    - /remove keyword \<keyword-id\>
    - /add signature \<signature\>
    - /remove signature \<signature-id\>
    - /dict
    - /collect \<model-name\> : REconverge가 생성한 클러스터로부터 dict/signature/keywords 수집.
    - /export label|dict \<filename\>

1. labtune: 모든 threat description 파일을 하나의 파일로 묶어서 관리.
2. [DONE] cli: 버그. 같은 레이블 이름이 중복으로 보이는 문제
3. [DONE] label에 매치된 클러스터 모아서 보기
4. labeler, labtune: label token에 대한 추천: suspicious, benign 매칭 비율 보여주기
5. cli: 클러스터의 Status, Tokens 요약 정보를 보여주기. Auto qualification & label matching 결과에 대한 검증용도.
6. STIX format 지원