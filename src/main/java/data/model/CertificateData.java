package data.model;

public class CertificateData {
    private String cn;
    private String sub;
    private String stDate;
    private String enDate;
    private String algorithm;

    public CertificateData(String cn, String sub, String stDate, String enDate, String algorithm) {
        this.cn = cn;
        this.sub = sub;
        this.stDate = stDate;
        this.enDate = enDate;
        this.algorithm = algorithm;
    }

    public String getCn() {
        return cn;
    }

    public void setCn(String cn) {
        this.cn = cn;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getStDate() {
        return stDate;
    }

    public void setStDate(String stDate) {
        this.stDate = stDate;
    }

    public String getEnDate() {
        return enDate;
    }

    public void setEnDate(String enDate) {
        this.enDate = enDate;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }
}
