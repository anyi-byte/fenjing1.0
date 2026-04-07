const taskFlashMessage = document.getElementById("task-flash-message");
const taskMessage = document.getElementById("task-message");
const taskChainMessage = document.getElementById("task-chain-message");
const interactiveMessage = document.getElementById("interactive-message");
const mainTaskForm = document.querySelector(".main-left form");
const interactiveTaskForm = document.querySelector(".cmd-input form");

let crackTaskRunning = false;
let interactiveTaskRunning = false;
let lastSuccessfulCrackTaskId = undefined;
const watchedTaskKeys = new Set();
const pageStateStorageKey = `fenjing-page-state:${window.location.pathname}`;
let lastPersistedPanels = "";

function loadPageState() {
  try {
    return JSON.parse(sessionStorage.getItem(pageStateStorageKey) || "{}");
  } catch (error) {
    console.error("Failed to load page state", error);
    return {};
  }
}

function writePageState(state) {
  try {
    sessionStorage.setItem(pageStateStorageKey, JSON.stringify(state));
  } catch (error) {
    console.error("Failed to save page state", error);
  }
}

function savePageState(patch) {
  writePageState({ ...loadPageState(), ...patch });
}

function clearPageStateFields(fields) {
  const state = loadPageState();
  for (const field of fields) {
    delete state[field];
  }
  writePageState(state);
}

function getFormState(form) {
  if (!form) {
    return {};
  }
  const state = {};
  for (const element of form.querySelectorAll("input, select, textarea")) {
    if (!element.id || element.type === "submit" || element.type === "hidden") {
      continue;
    }
    state[element.id] =
      element.type === "checkbox" ? element.checked : element.value;
  }
  return state;
}

function applyFormState(state) {
  if (!state) {
    return;
  }
  for (const [id, value] of Object.entries(state)) {
    const element = document.getElementById(id);
    if (!element) {
      continue;
    }
    if (element.type === "checkbox") {
      element.checked = Boolean(value);
    } else {
      element.value = value;
    }
  }
}

function persistFormState() {
  savePageState({
    mainForm: getFormState(mainTaskForm),
    interactiveForm: getFormState(interactiveTaskForm),
  });
}

function shouldAutoScroll(textarea) {
  if (!textarea) {
    return false;
  }
  return (
    textarea.scrollHeight - textarea.scrollTop - textarea.clientHeight < 24
  );
}

function updateTextarea(textarea, content) {
  if (!textarea) {
    return;
  }
  const stickToBottom = shouldAutoScroll(textarea);
  textarea.value = content;
  if (stickToBottom) {
    textarea.scrollTop = textarea.scrollHeight - textarea.clientHeight;
  }
}

function persistPanelState() {
  const panels = {
    flash: taskFlashMessage ? taskFlashMessage.value : "",
    message: taskMessage ? taskMessage.value : "",
    chain: taskChainMessage ? taskChainMessage.value : "",
    interactive: interactiveMessage ? interactiveMessage.value : "",
  };
  const panelsSerialized = JSON.stringify(panels);
  if (panelsSerialized === lastPersistedPanels) {
    return;
  }
  lastPersistedPanels = panelsSerialized;
  savePageState({ panels });
}

function restorePanelState() {
  const state = loadPageState();
  const panels = state.panels || {};
  updateTextarea(taskFlashMessage, panels.flash || "");
  updateTextarea(taskMessage, panels.message || "");
  updateTextarea(taskChainMessage, panels.chain || "");
  updateTextarea(interactiveMessage, panels.interactive || "");
  lastPersistedPanels = JSON.stringify({
    flash: panels.flash || "",
    message: panels.message || "",
    chain: panels.chain || "",
    interactive: panels.interactive || "",
  });
}

function clearTaskDisplay(taskKind) {
  if (taskKind === "interactive") {
    updateTextarea(interactiveMessage, "");
  } else {
    updateTextarea(taskFlashMessage, "");
    updateTextarea(taskMessage, "");
    updateTextarea(taskChainMessage, "");
  }
  persistPanelState();
}

function setCurrentCrackTaskId(taskId) {
  savePageState({ currentCrackTaskId: taskId });
}

function setCurrentInteractiveTaskId(taskId) {
  savePageState({ currentInteractiveTaskId: taskId });
}

function clearCurrentCrackTaskId(taskId) {
  const state = loadPageState();
  if (!taskId || state.currentCrackTaskId === taskId) {
    clearPageStateFields(["currentCrackTaskId"]);
  }
}

function clearCurrentInteractiveTaskId(taskId) {
  const state = loadPageState();
  if (!taskId || state.currentInteractiveTaskId === taskId) {
    clearPageStateFields(["currentInteractiveTaskId"]);
  }
}

function setLastSuccessfulCrackTaskId(taskId) {
  lastSuccessfulCrackTaskId = taskId;
  savePageState({ lastSuccessfulCrackTaskId: taskId });
}

function clearLastSuccessfulCrackTaskId(taskId) {
  const state = loadPageState();
  if (!taskId || state.lastSuccessfulCrackTaskId === taskId) {
    lastSuccessfulCrackTaskId = undefined;
    clearPageStateFields(["lastSuccessfulCrackTaskId"]);
  }
}

function handleMissingTask(taskId, taskKind) {
  if (taskKind === "interactive") {
    interactiveTaskRunning = false;
    clearCurrentInteractiveTaskId(taskId);
    return;
  }
  crackTaskRunning = false;
  clearCurrentCrackTaskId(taskId);
  clearLastSuccessfulCrackTaskId(taskId);
}

function watchTask(taskId, callback, options = {}) {
  const watchKey = `${options.taskKind || "default"}:${taskId}`;
  if (!taskId || watchedTaskKeys.has(watchKey)) {
    return;
  }
  watchedTaskKeys.add(watchKey);

  let timerId = null;
  const handleDataFn = (data) => {
    if (!data || data.code !== 200) {
      console.warn(`Task ${taskId} is unavailable`, data);
      if (timerId) {
        clearInterval(timerId);
      }
      watchedTaskKeys.delete(watchKey);
      handleMissingTask(taskId, options.taskKind);
      return;
    }

    const flashMessages = data["flash_messages"] || [];
    const messages = data["messages"] || [];
    const chainMessages = data["chain_messages"] || [];

    if (options.taskKind === "interactive") {
      updateTextarea(
        interactiveMessage,
        [...messages, ...flashMessages].join("\n")
      );
    } else {
      updateTextarea(
        taskFlashMessage,
        flashMessages[flashMessages.length - 1] || ""
      );
      updateTextarea(taskMessage, messages.join("\n"));
      updateTextarea(taskChainMessage, chainMessages.join("\n"));
    }

    persistPanelState();

    if (options.taskKind === "crack" && data.ready) {
      setLastSuccessfulCrackTaskId(data.taskid);
    }

    if (data.done) {
      if (timerId) {
        console.log(`Done! clear id: ${timerId}`);
        clearInterval(timerId);
      }
      watchedTaskKeys.delete(watchKey);
      if (options.taskKind === "interactive") {
        interactiveTaskRunning = false;
      } else {
        crackTaskRunning = false;
      }
      if (callback) {
        callback(data);
      }
    }
  };

  const intervalFn = () => {
    fetch("/watchTask", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ taskid: taskId }).toString(),
    })
      .then((response) => response.json())
      .then(handleDataFn)
      .catch((error) => {
        console.error(error);
      });
  };

  intervalFn();
  timerId = setInterval(intervalFn, 100);
}

function findParents(element) {
  let elements = [];
  let e = element;
  while (e) {
    elements.push(e);
    e = e.parentElement;
  }
  return elements;
}

function highlightCurrentPageButton() {
  for (let button of document.querySelectorAll(".icon-button").values()) {
    if (button.dataset.location == window.location.pathname) {
      button.classList.add("navbar-button-current");
    }
  }
}

function onClickNavbarButton(event) {
  let button = findParents(event.target).filter((e) =>
    e.classList.contains("icon-button")
  )[0];
  if (!button) {
    throw Error("Button not found");
  }
  if (!button.dataset.location) {
    alert("该页面暂未开放。");
    return;
  }
  window.location = button.dataset.location;
}

function onSubmitInteractiveTask(event) {
  event.preventDefault();
  if (interactiveTaskRunning) {
    alert("宸茬粡鏈夋鍦ㄨ繍琛岀殑浠诲姟浜嗭紒");
    return;
  }
  let formData = new FormData(event.target);
  if (!lastSuccessfulCrackTaskId) {
    alert("还没有完成分析，请先在左侧表单开始分析。");
    return;
  }
  formData.set("last_task_id", lastSuccessfulCrackTaskId);
  fetch("/createTask", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(formData).toString(),
  })
    .then((response) => response.json())
    .then((data) => {
      interactiveTaskRunning = true;
      if (!data.taskid) {
        console.log("鏈煡閿欒锛氭病鏈塈D");
        console.log(data);
        return;
      }
      persistFormState();
      setCurrentInteractiveTaskId(data.taskid);
      clearTaskDisplay("interactive");
      watchTask(data.taskid, undefined, { taskKind: "interactive" });
    })
    .catch((error) => {
      console.error(error);
    });
}

function onSubmitGeneralCrackPathTask(event, formChecker) {
  event.preventDefault();
  if (crackTaskRunning) {
    alert("宸茬粡鏈夋鍦ㄨ繍琛岀殑浠诲姟浜嗭紒");
    return;
  }
  let formData = new FormData(event.target);
  if (!formChecker(formData)) {
    return;
  }
  fetch("/createTask", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(formData).toString(),
  })
    .then((response) => response.json())
    .then((data) => {
      crackTaskRunning = true;
      if (!data.taskid) {
        console.log("鏈煡閿欒锛氭病鏈塈D");
        console.log(data);
        return;
      }
      persistFormState();
      setCurrentCrackTaskId(data.taskid);
      clearTaskDisplay("crack");
      let onTaskSuccess = (taskData) => {
        if (taskData.success || taskData.ready) {
          setLastSuccessfulCrackTaskId(taskData.taskid);
        }
      };
      watchTask(data.taskid, onTaskSuccess, { taskKind: "crack" });
    })
    .catch((error) => {
      console.error(error);
    });
}

function bindFormPersistence(form) {
  if (!form) {
    return;
  }
  form.addEventListener("input", persistFormState);
  form.addEventListener("change", persistFormState);
}

function restorePageState() {
  const state = loadPageState();
  applyFormState(state.mainForm);
  applyFormState(state.interactiveForm);
  restorePanelState();

  if (state.lastSuccessfulCrackTaskId) {
    lastSuccessfulCrackTaskId = state.lastSuccessfulCrackTaskId;
  }
  if (state.currentCrackTaskId) {
    watchTask(state.currentCrackTaskId, (data) => {
      if (data.success || data.ready) {
        setLastSuccessfulCrackTaskId(data.taskid);
      }
    }, { taskKind: "crack" });
  }
  if (state.currentInteractiveTaskId) {
    watchTask(state.currentInteractiveTaskId, undefined, {
      taskKind: "interactive",
    });
  }
}

highlightCurrentPageButton();
bindFormPersistence(mainTaskForm);
bindFormPersistence(interactiveTaskForm);
restorePageState();

// ============================================================
// Theme Switcher
// ============================================================

function switchTheme(themeName) {
  document.documentElement.setAttribute("data-theme", themeName);
  localStorage.setItem("fenjing-theme", themeName);
  updateThemeButtons(themeName);
}

function updateThemeButtons(activeTheme) {
  var buttons = document.querySelectorAll(".theme-btn");
  for (var i = 0; i < buttons.length; i++) {
    var btn = buttons[i];
    if (btn.getAttribute("data-theme") === activeTheme) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  }
}

// Initialize theme on page load
(function initTheme() {
  var savedTheme = localStorage.getItem("fenjing-theme") || "neon";
  document.documentElement.setAttribute("data-theme", savedTheme);
  updateThemeButtons(savedTheme);
})();
