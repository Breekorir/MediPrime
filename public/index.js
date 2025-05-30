

    const toggleBtn = document.getElementById('menu-toggle');
    // We now want to select the UL element inside the nav, not the nav itself
    const navUl = document.querySelector('#nav-links'); // Select the ul inside #nav-links

    toggleBtn.addEventListener('click', () => {
      navUl.classList.toggle('nav-links'); // Toggle the class on the ul
    });
// Check if the browser supports the Web Speech API