# rapidscanner 结果整理

使用rapidscanner扫描完，我们可以把结果导出来，然后用该工具导入到sqlite3 数据库，方便做下一步的自动化渗透

## 代码

```python
import sqlite3,re

conn= sqlite3.connect('test.db')
cursor=conn.cursor()
def init_table():    
    print('Opened database successfully')
    
    sql = """CREATE TABLE Ip_result 
    (id INTEGER PRIMARY KEY autoincrement    NOT NULL,
    ip TEXT    NOT NULL,
    port TEXT  NOT NULL,
    protocol TEXT    NOT NULL,
    banner TEXT     NOT NULL,
    insert_mark  TEXT  NOT NULL


    )"""
    cursor.execute(sql)
    conn.commit()
    print('init table successfully')
    

def insert_data(ip_resut,insert_mark):
    sql="INSERT INTO Ip_result(ip,port,protocol,banner,insert_mark) VALUES(?,?,?,?,?);" 
    
    cursor.execute(sql,(ip_resut['ip'],ip_resut['port'],ip_resut['protocol'],ip_resut['banner'],insert_mark))
      
    conn.commit()

def getFile(file,insert_mark):
    with open(file) as f:
        for result in f.readlines():            
            if '[' in result:
                _res = result.split('[')
                __res = re.sub('\s+', ' ',_res[0])  

                ip=(__res.split()[0]).split(":")[0]
                port=(__res.split()[0]).split(":")[1]
                protocol=__res.split()[1]
                banner = _res[1].replace("]","")
            else:
                __res = re.sub('\s+',' ',result)
                
                ip=(__res.split()[0]).split(":")[0]
                port=(__res.split()[0]).split(":")[1]
                banner=""  
                if len(__res.split())>1:
                    protocol=__res.split()[1]
                else:
                    protocol=""         
            ip_resut={'ip':ip,'port':port,'protocol':protocol,'banner':banner}
            insert_data(ip_resut,insert_mark)
              

if __name__ == "__main__":
    init_table()
    getFile("scan_result.txt","20201201")            
```



## 最终结果

<img src="img\image-20201201165835271.png" style="zoom:67%;" />



## 自己写分组查询语句或者根据端口、Banner查数据

``` sqlite
SELECT  port,count(port) from Ip_result ir  group by port;
SELECT ip||":"||port from Ip_result ir where  ir.port ='7002';

```

