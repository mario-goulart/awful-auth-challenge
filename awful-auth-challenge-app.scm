(load "awful-auth-challenge")
(import awful-auth-challenge)

(define (challenge-solver challenge-vector answer challenge-dimensions)
  ;; challenge-solver is the secret key
  ;;
  ;; challenge-vector: a line x columns vectors of numbers in the range [0..99]
  ;; answer: the user-provided answer to the challenge (a string)
  ;; challenge-dimensions: a pair (<lines> . <columns>)
  ;;
  ;; The correct challenge answer for this example is the number at
  ;; line 1 and column 2
  (let ((answer (string->number answer))
        (num-lines (car challenge-dimensions)))
    (and answer
         (= answer (vector-ref challenge-vector
                               (+ num-lines 2))))))

;; Launch the challenge app
(awful-auth-challenge "/" challenge-solver)
