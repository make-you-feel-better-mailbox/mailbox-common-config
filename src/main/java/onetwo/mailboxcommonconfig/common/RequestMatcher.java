package onetwo.mailboxcommonconfig.common;

import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;

import java.util.List;

public interface RequestMatcher {

    List<MvcRequestMatcher> getMvcRequestMatcherArray();
}
