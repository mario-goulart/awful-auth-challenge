(module awful-auth-challenge (awful-auth-challenge)

(import chicken scheme)
(use data-structures extras files irregex posix srfi-1 srfi-13 srfi-18 utils)
(use (except awful sid) http-session spiffy-cookies spiffy)

(define (awful-auth-challenge base-dir challenge-solver
                              #!key (css (make-pathname base-dir
                                                        "awful-auth-challenge.css"))
                                    (max-login-attempts 3)
                                    (challenge-dimensions '(15 . 15)) ;; (lines . columns)
                                    (ip-block-time 60) ;; 1 min
                                    vhost-root-path)

  (unless (string-suffix? "/" base-dir)
    (set! base-dir (string-append base-dir "/")))

  (define base-regex (string-append base-dir "*.*"))

  (define-app awful-auth-challenge
    matcher: (lambda (path)
               (irregex-match? base-regex path))
    parameters: ((enable-sxml #t)
                 (main-page-path base-dir)
                 (login-page-path (make-pathname base-dir "login"))
                 (session-cookie-name "awful-auth-challenge")
                 (page-doctype "<!DOCTYPE HTML>"))

    (define challenge-max (* (car challenge-dimensions)
                             (cdr challenge-dimensions)))

    (define (make-challenge)
      (map (lambda (_)
             (number->string (random 100)))
           (iota challenge-max)))

    (define (render-challenge challenge)
      (let* ((max-lines (car challenge-dimensions))
             (max-cells (cdr challenge-dimensions))
             (lines (chop challenge max-lines)))
        `(table
          ,@(let ((col-idxs
                   `(tr ,@(append
                           (cons `(td "")
                                 (map (lambda (i)
                                        `(td (@ (class "col-idxs")) ,i))
                                      (iota max-cells)))
                           '((td ""))))))
              (append
               (cons col-idxs
                     (map (lambda (line line-idx)
                            (let ((cells (map (lambda (cell)
                                                `(td ,cell))
                                              line))
                                  (idx `(td (@ (class "line-idxs"))
                                            ,line-idx)))
                              `(tr ,(append (cons idx cells)
                                            (list idx)))))
                          lines
                          (iota max-lines)))
               (list col-idxs))))))

    (define (render-auth-form page)
      `(center
        (form (@ (action ,(login-page-path))
                 (method "post"))
              ,(let ((challenge (make-challenge)))
                 `(,(render-challenge challenge)
                   (input (@ (type "hidden")
                             (name "challenge")
                             (value ,(string-intersperse challenge))))
                   (input (@ (type "hidden")
                             (name "page")
                             (value ,page)))
                   (input (@ (type "password")
                             (name "answer")
                             (autofocus)))
                   (input (@ (type "submit")
                             (value "?"))))))))

    (define (render-game-over)
      `(div (@ (id "game-over"))
            "GAME OVER"))

    ;;;
    ;;; Control the number of login attempts
    ;;;

    (define *login-attempts* '())
    (define login-attempts-mutex (make-mutex))

    (define (login-attempts-gc!)
      (let ((new-db '()))
        (for-each (lambda (attempt)
                    (let ((latest-attempt (cadr attempt)))
                      (when (> (+ latest-attempt ip-block-time)
                               (current-seconds))
                        (set! new-db (cons attempt new-db)))))
                  *login-attempts*)
        (set! *login-attempts* new-db)))

    (define (add-login-attempt!)
      (let* ((ip (remote-address))
             (ip-attempts (alist-ref ip *login-attempts* equal?)))
        (set! *login-attempts*
          (alist-update! ip
                         (if ip-attempts
                             (cons (current-seconds)
                                   (if (> (length ip-attempts)
                                          max-login-attempts)
                                       (take ip-attempts
                                             (- max-login-attempts 1))
                                       ip-attempts))
                             (list (current-seconds)))
                         *login-attempts*))))

    (define (ip-blocked?)
      (mutex-lock! login-attempts-mutex)
      (login-attempts-gc!)
      (let* ((attempts (alist-ref (remote-address) *login-attempts* equal? '()))
             (blocked? (>= (length attempts) max-login-attempts)))
        (mutex-unlock! login-attempts-mutex)
        blocked?))

    (define (maybe-block-ip)
      (mutex-lock! login-attempts-mutex)
      (login-attempts-gc!)
      (add-login-attempt!)
      (mutex-unlock! login-attempts-mutex))

    (define (release-ip!)
      (mutex-lock! login-attempts-mutex)
      (set! *login-attempts*
        (alist-delete (remote-address) *login-attempts* equal?))
      (mutex-unlock! login-attempts-mutex))


    ;;;
    ;;; Pages
    ;;;

    ;;; The page definer
    (define (define-auth-page matcher handler #!key (method 'get))
      (define-page matcher
        (let ((body
               (lambda (path content)
                 (let ((sid (read-cookie (session-cookie-name))))
                   (if (and sid (session-valid? sid))
                       (begin
                         (session-refresh! sid)
                         (content))
                       (redirect-to (string-append
                                     (login-page-path)
                                     "?page=" path)))))))
          (cond ((irregex? matcher)
                 (lambda (path)
                   (body path (lambda () (handler path)))))
                ((procedure? matcher)
                 (lambda args
                   (body (main-page-path)
                         (lambda () (apply handler args)))))
                ((string? matcher)
                 (lambda ()
                   (body matcher handler)))
                (else (error 'define-page* "Invalid matcher type" matcher))))
        method: method
        css: css
        vhost-root-path: vhost-root-path))

    ;;; The main page to be displayed after a successful
    ;;; authentication
    (define-auth-page (main-page-path)
      (lambda ()
        `((div (@ (id "congrats"))
               "Congrats!")
          (div (@ (id "restart"))
               (a (@ (href ,(make-pathname base-dir "logout")))
                  "Restart the challenge"))))
      vhost-root-path: vhost-root-path)

    ;;; The logout page
    (define-page (make-pathname (main-page-path) "logout")
      (lambda ()
        (and-let* ((sid (read-cookie (session-cookie-name)))
                   ((session-valid? sid)))
          (session-destroy! sid))
        (redirect-to (login-page-path)))
      vhost-root-path: vhost-root-path)

    ;;; The login (challenge) page
    (define-page (login-page-path)
      (lambda ()
        (with-request-variables ((challenge (nonempty as-string))
                                 (answer (nonempty as-string))
                                 (page (nonempty as-string)))
          (cond
           ((ip-blocked?)
            (render-game-over))
           ((and challenge answer)
            (let* ((challenge-numbers
                    (list->vector
                     (map string->number (string-split challenge))))
                   (right-answer?
                    (challenge-solver challenge-numbers
                                      answer
                                      challenge-dimensions)))
              (cond (right-answer?
                     (release-ip!)
                     (let ((sid (session-create)))
                       ((session-cookie-setter) sid)
                       (redirect-to (or page (main-page-path)))))
                    (else
                     (maybe-block-ip)
                     (if (ip-blocked?)
                         (render-game-over)
                         (render-auth-form page))))))
           (else (render-auth-form page)))))
      css: css
      vhost-root-path: vhost-root-path
      method: '(get post))

    ))
) ;; end module
