package io.moj.java.sdk.model.push;

import com.google.gson.annotations.SerializedName;

import java.util.Locale;

/**
 * Model object for an observer transport.
 * Created by skidson on 16-02-16.
 */
public class Transport {

    public static final String TYPE = "Type";
    public static final String DEVICE_REGISTRATION_ID = "DeviceRegistrationId";
    public static final String DEVICE_TOKEN = "DeviceToken";
    public static final String ALERT_BODY = "AlertBody";
    public static final String ALERT_SOUND = "AlertSound";
    public static final String ALERT_CATEGORY = "AlertCategory";
    public static final String BADGE = "Badge";
    public static final String ADDRESS = "Address";
    public static final String HOST_NAME = "HostName";
    public static final String TOPIC = "Topic";
    public static final String PORT = "Port";
    public static final String CONNECTION_STRING = "ConnectionString";
    public static final String COLLECTION_NAME = "CollectionName";
    public static final String IDENTIFIER = "Identifier";
    public static final String HUB_NAME = "HubName";
    public static final String CALLBACK = "Callback";
    public static final String CLIENT_ID = "ClientId";
    public static final String USER_NAME = "UserName";
    public static final String PASSWORD = "Password";

    @SerializedName("Type")
    private Type type;

    // Android
    private String DeviceRegistrationId;

    // Apple
    private String AppId;
    private String DeviceToken;
    private String AlertBody;
    private String AlertSound;
    private String AlertCategory;
    private Integer Badge;

    // HttpPost
    private String Address;

    // Mqtt
    private String HostName;
    private String Topic;
    private Integer Port;

    // MongoDB
    private String ConnectionString;
    private String CollectionName;
    private MongoIdentifierType Identifier;

    // SignalR
    private String HubName;
    private String Callback;

    // Shared
    private String ClientId;
    private String UserName;
    private String Password;

    public Transport() {}

    public Transport(Type type) {
        this.type = type;
    }

    public String getAddress() {
        return Address;
    }

    public String getAlertBody() {
        return AlertBody;
    }

    public String getAlertCategory() {
        return AlertCategory;
    }

    public String getAlertSound() {
        return AlertSound;
    }

    public int getBadge() {
        return Badge;
    }

    public String getCallback() {
        return Callback;
    }

    public String getClientId() {
        return ClientId;
    }

    public String getCollectionName() {
        return CollectionName;
    }

    public String getConnectionString() {
        return ConnectionString;
    }

    public String getDeviceRegistrationId() {
        return DeviceRegistrationId;
    }

    public String getDeviceToken() {
        return DeviceToken;
    }

    public String getHostName() {
        return HostName;
    }

    public String getHubName() {
        return HubName;
    }

    public MongoIdentifierType getIdentifier() {
        return Identifier;
    }

    public String getPassword() {
        return Password;
    }

    public int getPort() {
        return Port;
    }

    public String getTopic() {
        return Topic;
    }

    public Type getType() {
        return type;
    }

    public String getUserName() {
        return UserName;
    }

    public void setAddress(String address) {
        Address = address;
    }

    public void setAlertBody(String alertBody) {
        AlertBody = alertBody;
    }

    public void setAlertCategory(String alertCategory) {
        AlertCategory = alertCategory;
    }

    public void setAlertSound(String alertSound) {
        AlertSound = alertSound;
    }

    public void setCallback(String callback) {
        Callback = callback;
    }

    public void setClientId(String clientId) {
        ClientId = clientId;
    }

    public void setCollectionName(String collectionName) {
        CollectionName = collectionName;
    }

    public void setConnectionString(String connectionString) {
        ConnectionString = connectionString;
    }

    public void setDeviceRegistrationId(String deviceRegistrationId) {
        DeviceRegistrationId = deviceRegistrationId;
    }

    public void setDeviceToken(String deviceToken) {
        DeviceToken = deviceToken;
    }

    public void setHostName(String hostName) {
        HostName = hostName;
    }

    public void setHubName(String hubName) {
        HubName = hubName;
    }

    public void setIdentifier(MongoIdentifierType identifier) {
        Identifier = identifier;
    }

    public void setPassword(String password) {
        Password = password;
    }

    public void setTopic(String topic) {
        Topic = topic;
    }

    public void setType(Type type) {
        this.type = type;
    }

    public void setUserName(String userName) {
        UserName = userName;
    }

    public String getAppId() {
        return AppId;
    }

    public void setAppId(String appId) {
        AppId = appId;
    }

    public void setBadge(Integer badge) {
        Badge = badge;
    }

    public void setPort(Integer port) {
        Port = port;
    }

    @Override
    public String toString() {
        return "Transport{" +
                "type=" + type +
                ", DeviceRegistrationId='" + DeviceRegistrationId + '\'' +
                ", AppId='" + AppId + '\'' +
                ", DeviceToken='" + DeviceToken + '\'' +
                ", AlertBody='" + AlertBody + '\'' +
                ", AlertSound='" + AlertSound + '\'' +
                ", AlertCategory='" + AlertCategory + '\'' +
                ", Badge=" + Badge +
                ", Address='" + Address + '\'' +
                ", HostName='" + HostName + '\'' +
                ", Topic='" + Topic + '\'' +
                ", Port=" + Port +
                ", ConnectionString='" + ConnectionString + '\'' +
                ", CollectionName='" + CollectionName + '\'' +
                ", Identifier=" + Identifier +
                ", HubName='" + HubName + '\'' +
                ", Callback='" + Callback + '\'' +
                ", ClientId='" + ClientId + '\'' +
                ", UserName='" + UserName + '\'' +
                ", Password='" + Password + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Transport transport = (Transport) o;

        if (type != transport.type) return false;
        if (DeviceRegistrationId != null ? !DeviceRegistrationId.equals(transport.DeviceRegistrationId) : transport.DeviceRegistrationId != null)
            return false;
        if (AppId != null ? !AppId.equals(transport.AppId) : transport.AppId != null) return false;
        if (DeviceToken != null ? !DeviceToken.equals(transport.DeviceToken) : transport.DeviceToken != null)
            return false;
        if (AlertBody != null ? !AlertBody.equals(transport.AlertBody) : transport.AlertBody != null) return false;
        if (AlertSound != null ? !AlertSound.equals(transport.AlertSound) : transport.AlertSound != null) return false;
        if (AlertCategory != null ? !AlertCategory.equals(transport.AlertCategory) : transport.AlertCategory != null)
            return false;
        if (Badge != null ? !Badge.equals(transport.Badge) : transport.Badge != null) return false;
        if (Address != null ? !Address.equals(transport.Address) : transport.Address != null) return false;
        if (HostName != null ? !HostName.equals(transport.HostName) : transport.HostName != null) return false;
        if (Topic != null ? !Topic.equals(transport.Topic) : transport.Topic != null) return false;
        if (Port != null ? !Port.equals(transport.Port) : transport.Port != null) return false;
        if (ConnectionString != null ? !ConnectionString.equals(transport.ConnectionString) : transport.ConnectionString != null)
            return false;
        if (CollectionName != null ? !CollectionName.equals(transport.CollectionName) : transport.CollectionName != null)
            return false;
        if (Identifier != transport.Identifier) return false;
        if (HubName != null ? !HubName.equals(transport.HubName) : transport.HubName != null) return false;
        if (Callback != null ? !Callback.equals(transport.Callback) : transport.Callback != null) return false;
        if (ClientId != null ? !ClientId.equals(transport.ClientId) : transport.ClientId != null) return false;
        if (UserName != null ? !UserName.equals(transport.UserName) : transport.UserName != null) return false;
        return Password != null ? Password.equals(transport.Password) : transport.Password == null;

    }

    @Override
    public int hashCode() {
        int result = type != null ? type.hashCode() : 0;
        result = 31 * result + (DeviceRegistrationId != null ? DeviceRegistrationId.hashCode() : 0);
        result = 31 * result + (AppId != null ? AppId.hashCode() : 0);
        result = 31 * result + (DeviceToken != null ? DeviceToken.hashCode() : 0);
        result = 31 * result + (AlertBody != null ? AlertBody.hashCode() : 0);
        result = 31 * result + (AlertSound != null ? AlertSound.hashCode() : 0);
        result = 31 * result + (AlertCategory != null ? AlertCategory.hashCode() : 0);
        result = 31 * result + (Badge != null ? Badge.hashCode() : 0);
        result = 31 * result + (Address != null ? Address.hashCode() : 0);
        result = 31 * result + (HostName != null ? HostName.hashCode() : 0);
        result = 31 * result + (Topic != null ? Topic.hashCode() : 0);
        result = 31 * result + (Port != null ? Port.hashCode() : 0);
        result = 31 * result + (ConnectionString != null ? ConnectionString.hashCode() : 0);
        result = 31 * result + (CollectionName != null ? CollectionName.hashCode() : 0);
        result = 31 * result + (Identifier != null ? Identifier.hashCode() : 0);
        result = 31 * result + (HubName != null ? HubName.hashCode() : 0);
        result = 31 * result + (Callback != null ? Callback.hashCode() : 0);
        result = 31 * result + (ClientId != null ? ClientId.hashCode() : 0);
        result = 31 * result + (UserName != null ? UserName.hashCode() : 0);
        result = 31 * result + (Password != null ? Password.hashCode() : 0);
        return result;
    }

    public static Transport forAndroid(String deviceRegistrationId) {
        Transport t = new Transport(Type.ANDROID);
        t.setDeviceRegistrationId(deviceRegistrationId);
        return t;
    }

    public static Transport forApple(String appId, String deviceToken, String alertBody, String alertSound,
                                     String alertCategory, Integer badge) {
        Transport t = new Transport(Type.APPLE);
        t.setAppId(appId);
        t.setDeviceToken(deviceToken);
        t.setAlertBody(alertBody);
        t.setAlertSound(alertSound);
        t.setAlertCategory(alertCategory);
        t.setBadge(badge);
        return t;
    }

    public static Transport forHttpPost(String address) {
        return forHttpPost(address, null, null);
    }

    public static Transport forHttpPost(String address, String username, String password) {
        Transport t = new Transport(Type.HTTP_POST);
        t.setAddress(address);
        t.setUserName(username);
        t.setPassword(password);
        return t;
    }

    public static Transport forMongoDb(String connectionString, String collectionName, MongoIdentifierType identifier) {
        Transport t = new Transport(Type.MONGO_DB);
        t.setConnectionString(connectionString);
        t.setCollectionName(collectionName);
        t.setIdentifier(identifier);
        return t;
    }

    public static Transport forMqtt(String hostName, Integer port, String topic) {
        return forMqtt(hostName, port, topic, null);
    }

    public static Transport forMqtt(String hostName, Integer port, String topic, String clientId) {
        return forMqtt(hostName, port, topic, clientId, null, null);
    }

    public static Transport forMqtt(String hostName, Integer port, String topic, String clientId, String username,
                                    String password) {
        Transport t = new Transport(Type.MQTT);
        t.setHostName(hostName);
        t.setPort(port);
        t.setTopic(topic);
        t.setClientId(clientId);
        t.setUserName(username);
        t.setPassword(password);
        return t;
    }

    public static Transport forSignalR(String clientId, String hubName) {
        return forSignalR(clientId, hubName, null);
    }

    public static Transport forSignalR(String clientId, String hubName, String callback) {
        Transport t = new Transport(Type.SIGNAL_R);
        t.setClientId(clientId);
        t.setHubName(hubName);
        t.setCallback(callback);
        return t;
    }

    public enum Type {
        @SerializedName("Android")
        ANDROID("Android", "gcm://%s"),

        // TODO update the idFormat of the other transports pending Connery's documentation
        @SerializedName("Apple")
        APPLE("Apple", "apn://%s"),

        @SerializedName("HttpPost")
        HTTP_POST("HttpPost", "%s"),

        @SerializedName("MongoDB")
        MONGO_DB("MongoDB", "%s"),

        @SerializedName("Mqtt")
        MQTT("Mqtt", "%s"),

        @SerializedName("SignalR")
        SIGNAL_R("SignalR", "%s");

        private final String key;
        private final String idFormat;

        Type(String key, String idFormat) {
            this.key = key;
            this.idFormat = idFormat;
        }

        public String getKey() {
            return key;
        }

        public String getIdentifier(String... args) {
            return String.format(Locale.US, idFormat, args);
        }

        public static Type fromKey(String key) {
            for (Type type : values()) {
                if (type.getKey().equals(key))
                    return type;
            }
            return null;
        }
    }

    public enum MongoIdentifierType {
        @SerializedName("Default")
        DEFAULT("Default"),

        @SerializedName("Id")
        ID("Id"),

        @SerializedName("Guid")
        GUID("Guid");

        private final String key;

        MongoIdentifierType(String key) {
            this.key = key;
        }

        public String getKey() {
            return key;
        }

        public static MongoIdentifierType fromKey(String key) {
            for (MongoIdentifierType type : values()) {
                if (type.getKey().equals(key))
                    return type;
            }
            return null;
        }
    }
}
