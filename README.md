# sec-proj1 README

A project for the Convergence Security Project 1 course

## Features

- Detects XSS and SQL Injection in JavaScript/TypeScript
- Detects React JSX/TSX issues like dangerouslySetInnerHTML
- Detects SQLi and XSS patterns in Java (Spring/JSP)
- Inspired by and aligned with [Semgrep](https://semgrep.dev) community rules

---

## Getting Started

```bash
npm install
npm run compile
```

### Dev Mode
- Press `F5` in VSCode to run Extension Development Host
- Use `Ctrl+S` to auto-scan file

---

## Rule Summary

### XSS (Java/Spring)
| Rule ID                     | Description                                                     |
| --------------------------- | --------------------------------------------------------------- |
| `java.xss.response.write`   | Direct call to `HttpServletResponse.getWriter().write(tainted)` |
| `java.xss.writer.call`      | Tainted input written via `PrintWriter.print` / `println`       |
| `java.xss.spring.return`    | Spring MVC controller method returns tainted string             |
| `java.xss.wrapper.override` | Custom `HttpServletRequestWrapper` returns tainted data         |
| `java.xss.jaxws.return`     | `@WebMethod` endpoint returns tainted value                     |

---

### XSS (JS/TS/React)
| Rule ID                                | Description                                                    |
| -------------------------------------- | -------------------------------------------------------------- |
| `js.xss.react.dangerouslysetinnerhtml` | React `dangerouslySetInnerHTML` usage                          |
| `js.xss.react.ref.assignment`          | React `ref.current.innerHTML / outerHTML`                      |
| `js.xss.dom.assignment`                | DOM `innerHTML / outerHTML` assignment                         |
| `js.xss.dom.inserthtml`                | `insertAdjacentHTML / setHTML` with dynamic input              |
| `js.xss.document.write`                | `document.write / writeln` with dynamic input                  |
| `js.xss.template.concat`               | HTML string built using `+` with dynamic input                 |
| `js.xss.response.send`                 | `res.send / res.write` with raw dynamic input                  |
| `js.xss.response.template`             | `res.send` with HTML + dynamic input                           |
| `js.xss.lambda.return`                 | AWS Lambda `return { body: ... }` with tainted value           |
| `js.xss.angular.elementref.assignment` | `ElementRef.nativeElement.innerHTML = ...` in Angular          |
| `js.xss.angular.bypass.trusthtml`      | `DomSanitizer.bypassSecurityTrustHtml(...)`                    |
| `js.xss.angular.sce.disable`           | `$sceProvider.enabled(false)` disables SCE                     |
| `js.xss.angular.sce.trustas`           | `$sce.trustAs / trustAsHtml` bypasses SCE                      |
| `js.xss.eval.dynamic`                  | `setTimeout`, `setInterval`, `Function(...)` with string input |
| `js.xss.script.src.assignment`         | Dynamic `script.src = ...` assignment                          |

---

### SQL Injection (Java/Spring)
| Rule ID                         | Description                                |
| ------------------------------- | ------------------------------------------ |
| `java.sqli.jdbc.concat`         | `Statement.executeQuery(... + ...)`        |
| `java.sqli.generic.taint`       | Tainted input flows into any SQL execution |
| `java.sqli.jpa.annotation`      | `@Query(... + ...)` with dynamic input     |
| `java.sqli.jpa.createquery`     | `em.createQuery(... + ...)`                |
| `java.sqli.spring.jdbctemplate` | `jdbcTemplate.query(... + ...)` with taint |
| `java.sqli.string.format`       | `String.format(...)` used to build SQL     |
| `java.sqli.jdo.newquery`        | `pm.newQuery(... + ...)` in JDO            |

---

### SQL Injection (JavaScript/Node.js)
| Rule ID                          | Description                                      |
| -------------------------------- | ------------------------------------------------ |
| `js.sqli.raw.concat`             | SQL string built via concatenation               |
| `js.sqli.raw.template`           | SQL built using template strings                 |
| `js.sqli.orm.sequelize.raw`      | `sequelize.query(...)` with tainted input        |
| `js.sqli.orm.knex.raw`           | `knex.raw(...)` with tainted input               |
| `js.sqli.orm.typeorm.query`      | `connection.query(...)` with tainted input       |
| `js.sqli.orm.typeorm.builder`    | `createQueryBuilder().where(...)` with taint     |
| `js.sqli.orm.prisma.raw`         | `prisma.$queryRaw(...)` with tainted input       |
| `js.sqli.orm.mikroorm.builder`   | MikroORM's `createQueryBuilder().where(...)`     |
| `js.taint.source.request`        | Taint from `req.query`, `req.body`, `req.params` |
| `js.taint.propagation.parameter` | Taint propagation via function parameters        |

---
