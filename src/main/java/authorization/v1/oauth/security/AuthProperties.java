package authorization.v1.oauth.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Component
@Validated
@ConfigurationProperties("aw.auth")
@Getter
@Setter
public class AuthProperties {

    @NotBlank
    private String providerUri;

    @NotNull
    private JksProperties jks;

    public String getProdiderUri(){
        return providerUri;
    }

    public void setProviderUri(String providerUri){
        this.providerUri = providerUri;
    }

    public JksProperties getJks(){
        return jks;
    }
    @Getter
    @Setter
    static class JksProperties{

        @NotBlank
        private String keypass;

        @NotBlank
        private String storepass;

        @NotBlank
        private String alias;

        @NotBlank
        private String path;
    }
}
