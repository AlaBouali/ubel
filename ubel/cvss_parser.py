from cvss import CVSS2, CVSS3, CVSS4

class CVSS_Parser:

    @staticmethod
    def parse(vector:str):
        try:
            if vector.startswith('CVSS:4.'):
                data=CVSS4(vector)
            elif vector.startswith('CVSS:3.'):
                data=CVSS3(vector)
            else:
                data=CVSS3(vector)
            try:
                base_score=data.base_score
            except:
                base_score=None
            try:
                severity=data.severity
            except:
                severity="unknown"
            return str(base_score),severity
        except:
            return None,"unknown"
    
    @staticmethod
    def process_vulnerability(vuln:dict):
        if "severity" in vuln:
            severity_vector_list=vuln.get("severity",[])
            if severity_vector_list!=[]:
                severity_vector=severity_vector_list[0].get("score")
                if severity_vector_list[0].get("type").lower()=="ubuntu":
                    vuln["severity"]=severity_vector
                    vuln["severity_score"]=None
                    vuln["severity_vector"]=None
                    return
                else:
                    info=CVSS_Parser.parse(severity_vector)
                    vuln["severity"]=info[1]
                    vuln["severity_score"]=info[0]
                    vuln["severity_vector"]=severity_vector
                    if vuln["severity"] in [None,"","unknown"]:
                        if vuln["severity_score"]!=None:
                            severity_score=vuln["severity_score"] 
                            score = float(severity_score)
                            if 0.0 < score < 4.0:
                                severity = "low"
                            elif 4.0 <= score < 7.0:
                                severity = "medium"
                            elif 7.0 <= score < 9.0:
                                severity = "high"
                            elif 9.0 <= score <= 10.0:
                                severity = "critical"
                            else:
                                severity = "unknown"  # out-of-range protection
                            vuln["severity"]=severity
                    return
        vuln["severity"]="unknown"
        vuln["severity_score"]=None
        vuln["severity_vector"]=None
        