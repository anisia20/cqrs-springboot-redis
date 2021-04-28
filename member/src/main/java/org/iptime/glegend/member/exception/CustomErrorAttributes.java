package org.iptime.glegend.member.exception;

import lombok.extern.log4j.Log4j2;
import org.springframework.boot.web.reactive.error.DefaultErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebInputException;

import java.util.HashMap;
import java.util.Map;

@Log4j2
@Component
public class CustomErrorAttributes<T extends Throwable> extends DefaultErrorAttributes {

    @Override
    public Map<String, Object> getErrorAttributes(ServerRequest request, boolean includeStackTrace) {

        Map<String, Object> errorAttributes = new HashMap<String, Object>();
        Throwable e = getError(request);

        log.error("LK={}, errmsg={}, url={}, attributes={}",
                request.headers().asHttpHeaders().get("logkey"),
                e.getMessage(), request.uri().getPath(), request.attributes());

        HttpStatus errorStatus = determineHttpStatus(e);
        errorAttributes.put("status", errorStatus.value());
        errorAttributes.put("r", "999");
        errorAttributes.put("rd", "기타오류");

        return errorAttributes;
    }

    private HttpStatus determineHttpStatus(Throwable error) {
        if (error instanceof ResponseStatusException) {
            return ((ResponseStatusException) error).getStatus();
        }
        else if (error instanceof ServerWebInputException) {
            return ((ServerWebInputException) error).getStatus();
        }
        return HttpStatus.INTERNAL_SERVER_ERROR;
    }
}
