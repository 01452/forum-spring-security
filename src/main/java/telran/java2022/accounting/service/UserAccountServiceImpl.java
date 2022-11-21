package telran.java2022.accounting.service;

import java.time.LocalDate;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jmx.export.annotation.ManagedAttribute;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.java2022.accounting.dao.UserAccountRepository;
import telran.java2022.accounting.dto.RolesResponseDto;
import telran.java2022.accounting.dto.UserAccountResponseDto;
import telran.java2022.accounting.dto.UserRegisterDto;
import telran.java2022.accounting.dto.UserUpdateDto;
import telran.java2022.accounting.dto.exceptions.UserExistsException;
import telran.java2022.accounting.dto.exceptions.UserNotFoundException;
import telran.java2022.accounting.model.UserAccount;

@Service
@RequiredArgsConstructor
@ManagedResource
public class UserAccountServiceImpl implements UserAccountService, CommandLineRunner {
	final UserAccountRepository repository;
	final ModelMapper modelMapper;
	final PasswordEncoder passwordEncoder;
	@Value("${password.period:30}")
	long passwordPeriod;

	@ManagedAttribute
	public long getPasswordPeriod() {
		return passwordPeriod;
	}

	@ManagedAttribute
	public void setPasswordPeriod(long passwordPeriod) {
		this.passwordPeriod = passwordPeriod;
	}

	@Override
	public UserAccountResponseDto addUser(UserRegisterDto userRegisterDto) {
		if (repository.existsById(userRegisterDto.getLogin())) {
			throw new UserExistsException(userRegisterDto.getLogin());
		}
		UserAccount userAccount = modelMapper.map(userRegisterDto, UserAccount.class);
		String password = passwordEncoder.encode(userRegisterDto.getPassword());
		userAccount.setPassword(password);
		userAccount.setPasswordExpDate(LocalDate.now().plusDays(passwordPeriod));
		repository.save(userAccount);
		return modelMapper.map(userAccount, UserAccountResponseDto.class);
	}

	@Override
	public UserAccountResponseDto getUser(String login) {
		UserAccount userAccount = repository.findById(login).orElseThrow(() -> new UserNotFoundException());
		return modelMapper.map(userAccount, UserAccountResponseDto.class);
	}

	@Override
	public UserAccountResponseDto removeUser(String login) {
		UserAccount userAccount = repository.findById(login).orElseThrow(() -> new UserNotFoundException());
		repository.deleteById(login);
		return modelMapper.map(userAccount, UserAccountResponseDto.class);
	}

	@Override
	public UserAccountResponseDto editUser(String login, UserUpdateDto updateDto) {
		UserAccount userAccount = repository.findById(login).orElseThrow(() -> new UserNotFoundException());
		if (updateDto.getFirstName() != null) {
			userAccount.setFirstName(updateDto.getFirstName());
		}
		if (updateDto.getLastName() != null) {
			userAccount.setLastName(updateDto.getLastName());
		}
		repository.save(userAccount);
		return modelMapper.map(userAccount, UserAccountResponseDto.class);
	}

	@Override
	public RolesResponseDto changeRolesList(String login, String role, boolean isAddRole) {
		UserAccount userAccount = repository.findById(login).orElseThrow(() -> new UserNotFoundException());
		boolean res;
		if (isAddRole) {
			res = userAccount.addRole(role.toUpperCase());
		} else {
			res = userAccount.removeRole(role.toUpperCase());
		}
		if (res) {
			repository.save(userAccount);
		}
		return modelMapper.map(userAccount, RolesResponseDto.class);
	}

	@Override
	public void changePassword(String login, String newPassword) {
		UserAccount userAccount = repository.findById(login).orElseThrow(() -> new UserNotFoundException());
		String password = passwordEncoder.encode(newPassword);
		userAccount.setPassword(password);
		userAccount.setPasswordExpDate(LocalDate.now().plusDays(passwordPeriod));
		repository.save(userAccount);
	}

	@Override
	public void run(String... args) throws Exception {
		if (!repository.existsById("admin")) {
			String password = passwordEncoder.encode("admin");
			UserAccount userAccount = new UserAccount("admin", password, "", "");
			userAccount.addRole("MODERATOR");
			userAccount.addRole("ADMINISTRATOR");
			userAccount.setPasswordExpDate(LocalDate.now().plusDays(passwordPeriod));
			repository.save(userAccount);
		}

	}

}
