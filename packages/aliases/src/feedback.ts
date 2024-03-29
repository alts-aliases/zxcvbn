import scoring from "./scoring";

const feedback = {
  default_feedback: {
    warning: "",
    suggestions: [
      "Use a few words, avoid common phrases",
      "No need for symbols, digits, or uppercase letters",
    ],
  },
  get_feedback: function (score, sequence) {
    if (sequence.length === 0) {
      // starting feedback
      return this.default_feedback;
    }
    // no feedback if score is good or great.
    if (score > 2) {
      return {
        warning: "",
        suggestions: [],
      };
    }
    // tie feedback to the longest match for longer sequences
    let longest_match = sequence[0];
    const ref = sequence.slice(1);
    for (let i = 0, len = ref.length; i < len; i++) {
      const match = ref[i];
      if (match.token.length > longest_match.token.length) {
        longest_match = match;
      }
    }
    let feedback = this.get_match_feedback(
      longest_match,
      sequence.length === 1
    );
    const extra_feedback =
      "Add another word or two. Uncommon words are better.";
    if (feedback != null) {
      feedback.suggestions.unshift(extra_feedback);
      if (feedback.warning == null) {
        feedback.warning = "";
      }
    } else {
      feedback = {
        warning: "",
        suggestions: [extra_feedback],
      };
    }
    return feedback;
  },
  get_match_feedback: function (match, is_sole_match) {
    let layout;
    let warning;
    switch (match.pattern) {
      case "dictionary":
        return this.get_dictionary_match_feedback(match, is_sole_match);
      case "spatial":
        layout = match.graph.toUpperCase();
        warning =
          match.turns === 1
            ? "Straight rows of keys are easy to guess"
            : "Short keyboard patterns are easy to guess";
        return {
          warning: warning,
          suggestions: ["Use a longer keyboard pattern with more turns"],
        };
      case "repeat":
        warning =
          match.base_token.length === 1
            ? 'Repeats like "aaa" are easy to guess'
            : 'Repeats like "abcabcabc" are only slightly harder to guess than "abc"';
        return {
          warning: warning,
          suggestions: ["Avoid repeated words and characters"],
        };
      case "sequence":
        return {
          warning: "Sequences like abc or 6543 are easy to guess",
          suggestions: ["Avoid sequences"],
        };
      case "regex":
        if (match.regex_name === "recent_year") {
          return {
            warning: "Recent years are easy to guess",
            suggestions: [
              "Avoid recent years",
              "Avoid years that are associated with you",
            ],
          };
        }
        break;
      case "date":
        return {
          warning: "Dates are often easy to guess",
          suggestions: ["Avoid dates and years that are associated with you"],
        };
    }
  },
  get_dictionary_match_feedback: function (match, is_sole_match) {
    const warning =
      match.dictionary_name === "passwords"
        ? is_sole_match && !match.l33t && !match.reversed
          ? match.rank <= 10
            ? "This is a top-10 common password"
            : match.rank <= 100
            ? "This is a top-100 common password"
            : "This is a very common password"
          : match.guesses_log10 <= 4
          ? "This is similar to a commonly used password"
          : void 0
        : match.dictionary_name === "english_wikipedia"
        ? is_sole_match
          ? "A word by itself is easy to guess"
          : void 0
        : ["surnames", "male_names", "female_names"].includes(
            match.dictionary_name
          )
        ? is_sole_match
          ? "Names and surnames by themselves are easy to guess"
          : "Common names and surnames are easy to guess"
        : "";
    const suggestions = [] as string[];
    const word = match.token;
    if (word.match(scoring.START_UPPER)) {
      suggestions.push("Capitalization doesn't help very much");
    } else if (word.match(scoring.ALL_UPPER) && word.toLowerCase() !== word) {
      suggestions.push(
        "All-uppercase is almost as easy to guess as all-lowercase"
      );
    }
    if (match.reversed && match.token.length >= 4) {
      suggestions.push("Reversed words aren't much harder to guess");
    }
    if (match.l33t) {
      suggestions.push(
        "Predictable substitutions like '@' instead of 'a' don't help very much"
      );
    }
    const result = {
      warning: warning,
      suggestions: suggestions,
    };
    return result;
  },
};

export default feedback;
