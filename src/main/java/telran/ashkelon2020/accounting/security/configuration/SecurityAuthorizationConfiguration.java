package telran.ashkelon2020.accounting.security.configuration;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

//@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class SecurityAuthorizationConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	public void configure(WebSecurity web) {
		web.ignoring().antMatchers(HttpMethod.POST, "/account/register"); //проходит регистрация
	}
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.httpBasic();
		http.csrf().disable();
		http.authorizeRequests()
		.antMatchers(HttpMethod.GET)  //все гет-запросы
				.permitAll()
				
		.antMatchers(HttpMethod.POST, "/forum/posts/**") //поиск постов по тегам и периоду
				.permitAll()
				
		.antMatchers("/account/user/{login}/role/{role}**") //удаление и добавление ролей админом
				.hasRole("ADMIN")
				
		.antMatchers("/account/login**","/forum/post/{id}/like**") //залогиниться, поставить лайк
				.access("@customSecurity.checkExpDate(authentication.name) and hasAnyRole('USER','MODERATOR','ADMIN')")
				
		.antMatchers(HttpMethod.DELETE, "/account/user/{login}**") //удалить юзера
				.access("#login==authentication.name")
				
		.antMatchers(HttpMethod.PUT, "/account/user/{login}**") //апдейт юзера
				.access("@customSecurity.checkExpDate(authentication.name) and #login==authentication.name and hasAnyRole('USER','MODERATOR','ADMIN')")
			
		.antMatchers("/forum/post/{id}/comment/{author}**") //добавить коммент
				.access("@customSecurity.checkExpDate(authentication.name) and #author==authentication.name and hasAnyRole('USER','MODERATOR','ADMIN')")
			
		.antMatchers(HttpMethod.POST,"/forum/post/{author}**") //добавить пост
				.access("@customSecurity.checkExpDate(authentication.name) and #author==authentication.name and hasAnyRole('USER','MODERATOR','ADMIN')")
						
		.antMatchers("/forum/post/{id}**") //апдейт поста, удаление поста
				.access("@customSecurity.checkExpDate(authentication.name) and @customSecurity.checkPostAuthority(#id, authentication.name) or hasRole('MODERATOR')")
		
		.antMatchers("/account/password**")
				.authenticated()
		
		.anyRequest().permitAll();
		
		}
}

		
		
