package data.model;

public class FormCert {
    private String issuer;
    private String cn;
    private String organization;
    private String country;
    private String state;
    private String location;
    private String stDate;
    private String enDate;

    public FormCert() {
    }

    public FormCert(String issuer, String cn, String organization, String country, String state, String location) {
        this.issuer = issuer;
        this.cn = cn;
        this.organization = organization;
        this.country = country;
        this.state = state;
        this.location = location;
    }

    public FormCert(String issuer, String cn, String organization, String country, String state, String location, String stDate, String enDate) {
        this.issuer = issuer;
        this.cn = cn;
        this.organization = organization;
        this.country = country;
        this.state = state;
        this.location = location;
        this.stDate = stDate;
        this.enDate = enDate;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getCn() {
        return cn;
    }

    public void setCn(String cn) {
        this.cn = cn;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
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
}
