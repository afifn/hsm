package data.model;

public class KeyMechanism {
    private String key;
    private long mechanism;

    public KeyMechanism() {
    }



    public KeyMechanism(String key, long mechanism) {
        this.key = key;
        this.mechanism = mechanism;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public long getMechanism() {
        return mechanism;
    }

    public void setMechanism(long mechanism) {
        this.mechanism = mechanism;
    }

    @Override
    public String toString() {
        return key;
    }
}
