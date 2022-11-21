package telran.java2022.security.service;

import java.time.LocalDate;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.java2022.accounting.dao.UserAccountRepository;
import telran.java2022.accounting.model.UserAccount;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

	final UserAccountRepository repository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserAccount userAccount = repository.findById(username)
				.orElseThrow(() -> new UsernameNotFoundException(username));
		if (userAccount.getPasswordExpDate().isBefore(LocalDate.now())) {
			userAccount.addRole("timepassword");
		}
		String[] roles = userAccount.getRoles().stream().map(r -> "ROLE_" + r.toUpperCase()).toArray(String[]::new);
		return new User(username, userAccount.getPassword(), AuthorityUtils.createAuthorityList(roles));
	}

}
