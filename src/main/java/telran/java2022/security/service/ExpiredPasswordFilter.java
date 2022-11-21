package telran.java2022.security.service;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.GenericFilterBean;

@Service
public class ExpiredPasswordFilter extends GenericFilterBean {

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication != null && checkEndPoint(request.getMethod(), request.getServletPath())) {
			User user = (User) authentication.getPrincipal();
			if (user.getAuthorities().containsAll(AuthorityUtils.createAuthorityList("ROLE_TIMEPASSWORD"))) {
				response.addHeader("access_denied_reason", "password " + user.getUsername() + " change required");
				response.sendError(401);
				return;
			}
		}
		chain.doFilter(request, response);
	}

	private boolean checkEndPoint(String method, String path) {
		return !(("Put".equalsIgnoreCase(method) && path.matches("/account/password/?"))
				|| path.matches("/account/register/?") || path.matches("/forum/posts/?"));
	}

}
