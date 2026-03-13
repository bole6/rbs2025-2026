package com.zuehlke.securesoftwaredevelopment.controller;

import com.zuehlke.securesoftwaredevelopment.config.AuditLogger;
import com.zuehlke.securesoftwaredevelopment.config.SecurityUtil;
import com.zuehlke.securesoftwaredevelopment.domain.Person;
import com.zuehlke.securesoftwaredevelopment.domain.User;
import com.zuehlke.securesoftwaredevelopment.repository.PersonRepository;
import com.zuehlke.securesoftwaredevelopment.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.http.HttpSession;
import java.sql.SQLException;
import java.util.List;

@Controller

public class PersonsController {

    private static final Logger LOG = LoggerFactory.getLogger(PersonsController.class);
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(PersonRepository.class);

    private final PersonRepository personRepository;
    private final UserRepository userRepository;

    public PersonsController(PersonRepository personRepository, UserRepository userRepository) {
        this.personRepository = personRepository;
        this.userRepository = userRepository;
    }

    @GetMapping("/persons/{id}")
    @PreAuthorize("hasAuthority('VIEW_PERSON')")
    public String person(@PathVariable int id, Model model, HttpSession session) {
        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        model.addAttribute("CSRF_TOKEN", csrf);
        model.addAttribute("person", personRepository.get("" + id));
        model.addAttribute("username", userRepository.findUsername(id));
        return "person";
    }

    @GetMapping("/myprofile")
    @PreAuthorize("hasAuthority('VIEW_MY_PROFILE')")
    public String self(Model model, Authentication authentication, HttpSession session) {
        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        model.addAttribute("CSRF_TOKEN", csrf);
        User user = (User) authentication.getPrincipal();
        model.addAttribute("person", personRepository.get("" + user.getId()));
        model.addAttribute("username", userRepository.findUsername(user.getId()));
        return "person";
    }

    @DeleteMapping("/persons/{id}")
    @PreAuthorize("hasAuthority('UPDATE_PERSON')")
    public ResponseEntity<Void> person(@PathVariable int id) {
        User currentUser = SecurityUtil.getCurrentUser();
        boolean isAdmin = currentUser != null && currentUser.getUsername().equals("admin");
        if (!isAdmin && (currentUser == null || currentUser.getId() != id)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You can delete only your own profile");
        }

        personRepository.delete(id);
        userRepository.delete(id);

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/update-person")
    @PreAuthorize("hasAuthority('UPDATE_PERSON')")
    public String updatePerson(Person person,
                               String username,
                               HttpSession session,
                               @RequestParam(value= "csrfToken", required = false) String csrfToken
    ) {
        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        if(!csrf.equals(csrfToken)){
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "No CSRF For you hacker xexe");
        }
        User currentUser = SecurityUtil.getCurrentUser();
        int personId = Integer.parseInt(person.getId());
        boolean isAdmin = currentUser != null && currentUser.getUsername().equals("admin");
        if (!isAdmin && (currentUser == null || currentUser.getId() != personId)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You can update only your own profile");
        }
        personRepository.update(person);
        userRepository.updateUsername(personId, username);

        if (isAdmin) {
            return "redirect:/persons/" + person.getId();
        }
        return "redirect:/myprofile";
    }

    @GetMapping("/persons")
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    public String persons(Model model, HttpSession session) {
        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        model.addAttribute("CSRF_TOKEN", csrf);
        model.addAttribute("persons", personRepository.getAll());
        model.addAttribute("canViewPerson", SecurityUtil.hasPermission("VIEW_PERSON"));
        return "persons";
    }

    @GetMapping(value = "/persons/search", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    public List<Person> searchPersons(@RequestParam String searchTerm) throws SQLException {
        return personRepository.search(searchTerm);
    }
}
