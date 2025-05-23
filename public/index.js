
const toggleBtn = document.getElementById('menu-toggle');
const navLinks = document.getElementById('nav-links');

toggleBtn.addEventListener('click', () => {
  navLinks.classList.toggle('show');
});
// Check if the browser supports the Web Speech API
const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

if (SpeechRecognition) {
    const recognition = new SpeechRecognition();
    recognition.lang = 'en-US'; // set language
    recognition.interimResults = false; // only final results

    const micBtn = document.getElementById('micBtn');
    const searchInput = document.getElementById('searchInput');

    micBtn.addEventListener('click', () => {
        recognition.start(); // start listening
    });

    recognition.addEventListener('result', (event) => {
        const transcript = event.results[0][0].transcript;
        searchInput.value = transcript;
        // Optional: auto-submit or trigger search
        console.log("You said:", transcript);
    });

    recognition.addEventListener('end', () => {
        console.log("Voice input ended");
    });
} else {
    alert("Your browser doesn't support Speech Recognition");
}
recognition.addEventListener('result', (event) => {
    const transcript = event.results[0][0].transcript;
    searchInput.value = transcript;
    document.getElementById('searchForm').submit(); // or call your search function
});
