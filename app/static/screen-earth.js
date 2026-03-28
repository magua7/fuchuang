import * as THREE from "three";
import { OrbitControls } from "/static/vendor/OrbitControls.js";

const EARTH_RADIUS = 3.35;
const DEFAULT_TARGET = {
  name: "业务主站",
  label: "中国 · 业务区",
  lng: 112.9389,
  lat: 28.2282,
};

const FLOW_COLORS = {
  high: 0xec8f43,
  medium: 0xf3ae76,
  low: 0xd9a66b,
};

const TEXTURES = {
  earth: "/static/earth/earth.jpg",
  glow: "/static/earth/glow.png",
  gradient: "/static/earth/gradient.png",
  aperture: "/static/earth/aperture.png",
  lightColumn: "/static/earth/light_column.png",
  redCircle: "/static/earth/redCircle.png",
};

function buildLineGeometry(points) {
  const geometry = new THREE.BufferGeometry().setFromPoints(points);
  const line = new THREE.Line(
    geometry,
    new THREE.LineBasicMaterial({
      transparent: true,
      opacity: 0.34,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    })
  );
  return line;
}

function lonLatToVector3(radius, lng, lat) {
  const longitude = (-lng * Math.PI) / 180;
  const latitude = (lat * Math.PI) / 180;
  return new THREE.Vector3(
    radius * Math.cos(latitude) * Math.cos(longitude),
    radius * Math.sin(latitude),
    radius * Math.cos(latitude) * Math.sin(longitude)
  );
}

function formatCount(value) {
  return Number(value || 0).toLocaleString("zh-CN");
}

function buildArcCurve(start, end) {
  const middle = start.clone().add(end).multiplyScalar(0.5);
  const distance = start.distanceTo(end);
  const lift = EARTH_RADIUS + 1.05 + Math.min(distance * 0.24, 1.6);
  middle.normalize().multiplyScalar(lift);
  return new THREE.CatmullRomCurve3([start, middle, end]);
}

function createLabelNode() {
  const node = document.createElement("div");
  node.className = "threat-globe__label";
  node.hidden = true;
  return node;
}

function trimCnSuffix(value) {
  return String(value || "")
    .trim()
    .replace(/特别行政区/g, "")
    .replace(/自治区/g, "")
    .replace(/省/g, "")
    .replace(/市/g, "")
    .trim();
}

function compactFlowName(flow) {
  const country = String(flow.source_country || "").trim();
  const region = trimCnSuffix(flow.source_region || "");
  const city = trimCnSuffix(flow.source_city || "");
  const sourceLabel = String(flow.source_label || "").trim();
  const labelParts = sourceLabel
    .split(/[\\/|·]/)
    .map((item) => trimCnSuffix(item.replace(/\b[A-Z]{2}\b/g, "")))
    .filter(Boolean);
  const fallback = trimCnSuffix(flow.source_name || flow.source_bucket || "未知来源");

  if (country && country !== "中国") {
    if (labelParts.length) {
      return labelParts[labelParts.length - 1];
    }
    return trimCnSuffix(country) || fallback;
  }

  if (region) {
    return region;
  }

  return fallback || "未知来源";
}

function flagEmojiForCountry(country) {
  const map = {
    中国: "🇨🇳",
    新加坡: "🇸🇬",
    美国: "🇺🇸",
    英国: "🇬🇧",
    荷兰: "🇳🇱",
    德国: "🇩🇪",
    俄罗斯: "🇷🇺",
    日本: "🇯🇵",
    韩国: "🇰🇷",
    加拿大: "🇨🇦",
    法国: "🇫🇷",
    澳大利亚: "🇦🇺",
    印度: "🇮🇳",
    巴西: "🇧🇷",
    香港: "🇨🇳",
    台湾: "🇨🇳",
    中国香港: "🇨🇳",
    中国台湾: "🇨🇳",
  };
  return map[String(country || "").trim()] || "📍";
}

function compactFlowFlag(flow) {
  const country = String(flow.source_country || "").trim();
  if (country && country !== "未知") {
    return flagEmojiForCountry(country);
  }
  return flow.source_bucket === "本地" ? "🏠" : "📍";
}

function screenFlowDisplayName(flow) {
  const country = String(flow.source_country || "").trim();
  const region = trimCnSuffix(flow.source_region || "");
  const city = trimCnSuffix(flow.source_city || "");
  const sourceLabel = String(flow.source_label || "").trim();
  const parts = sourceLabel
    .split(/[\\/|·路]/)
    .map((item) => trimCnSuffix(String(item || "").replace(/\b[A-Z]{2}\b/g, "")))
    .filter(Boolean);
  const fallback = trimCnSuffix(String(flow.source_name || flow.source_bucket || "未知来源").replace(/\b[A-Z]{2}\b/g, ""));

  if (country && country !== "中国") {
    return parts.length ? parts[parts.length - 1] : trimCnSuffix(country) || fallback || "未知来源";
  }

  if (region) {
    return region;
  }

  if (parts.length >= 2) {
    return parts[1];
  }

  if (city) {
    return city;
  }

  return fallback || "未知来源";
}

function screenFlowBadge(flow) {
  const country = String(flow.source_country || "").trim();
  const map = {
    中国: "CN",
    新加坡: "SG",
    美国: "US",
    英国: "UK",
    荷兰: "NL",
    德国: "DE",
    俄罗斯: "RU",
    日本: "JP",
    韩国: "KR",
    加拿大: "CA",
    法国: "FR",
    澳大利亚: "AU",
    印度: "IN",
    巴西: "BR",
    香港: "CN",
    台湾: "CN",
    中国香港: "CN",
    中国台湾: "CN",
  };

  if (/^[A-Z]{2}$/.test(country)) {
    return country;
  }

  if (country && map[country]) {
    return map[country];
  }

  return flow.source_bucket === "本地" ? "LAN" : "NET";
}

export class ThreatEarthScreen {
  constructor(stageElement, labelsElement) {
    this.stageElement = stageElement;
    this.labelsElement = labelsElement;
    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(42, 1, 0.1, 100);
    this.camera.position.set(0.22, 0.46, 8.75);
    this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    this.renderer.setSize(100, 100, false);
    this.renderer.outputEncoding = THREE.sRGBEncoding;
    this.renderer.domElement.style.width = "100%";
    this.renderer.domElement.style.height = "100%";
    this.renderer.domElement.style.display = "block";
    this.controls = new OrbitControls(this.camera, this.renderer.domElement);
    this.controls.enablePan = false;
    this.controls.enableDamping = true;
    this.controls.dampingFactor = 0.08;
    this.controls.autoRotate = true;
    this.controls.autoRotateSpeed = 0.72;
    this.controls.minDistance = 7.2;
    this.controls.maxDistance = 12.8;
    this.controls.target.set(0, 0.12, 0);
    this.loader = new THREE.TextureLoader();
    this.textures = {};
    this.earthGroup = new THREE.Group();
    this.flowGroup = new THREE.Group();
    this.markerGroup = new THREE.Group();
    this.pulseGroup = new THREE.Group();
    this.animatedFlows = [];
    this.labelAnchors = [];
    this.targetMarker = null;
    this.frameId = 0;
    this.handleResize = this.handleResize.bind(this);
    this.animate = this.animate.bind(this);
  }

  async init() {
    this.stageElement.innerHTML = "";
    this.stageElement.appendChild(this.renderer.domElement);
    await this.loadTextures();
    this.setupScene();
    this.handleResize();
    window.addEventListener("resize", this.handleResize);
    this.animate();
  }

  destroy() {
    window.removeEventListener("resize", this.handleResize);
    if (this.frameId) {
      cancelAnimationFrame(this.frameId);
    }
    this.controls.dispose();
    this.renderer.dispose();
  }

  async loadTextures() {
    const load = (url) =>
      new Promise((resolve, reject) => {
        this.loader.load(url, resolve, undefined, reject);
      });

    const [earth, glow, gradient, aperture, lightColumn, redCircle] = await Promise.all([
      load(TEXTURES.earth),
      load(TEXTURES.glow),
      load(TEXTURES.gradient),
      load(TEXTURES.aperture),
      load(TEXTURES.lightColumn),
      load(TEXTURES.redCircle),
    ]);

    earth.encoding = THREE.sRGBEncoding;
    this.textures = { earth, glow, gradient, aperture, lightColumn, redCircle };
  }

  setupScene() {
    this.scene.add(this.earthGroup);
    this.earthGroup.add(this.flowGroup);
    this.earthGroup.add(this.markerGroup);
    this.earthGroup.add(this.pulseGroup);

    const ambientLight = new THREE.AmbientLight(0x7ecbff, 1.2);
    const keyLight = new THREE.DirectionalLight(0x8ed4ff, 1.7);
    keyLight.position.set(8, 6, 10);
    const rimLight = new THREE.PointLight(0x15d1ff, 1.2, 30);
    rimLight.position.set(-6, -3, -8);
    this.scene.add(ambientLight, keyLight, rimLight);

    this.createStarfield();
    this.createBackHalo();
    this.createEarthBody();
    this.createOrbitRings();
  }

  createStarfield() {
    const geometry = new THREE.BufferGeometry();
    const points = [];
    for (let index = 0; index < 1000; index += 1) {
      const radius = 18 + Math.random() * 16;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      points.push(
        radius * Math.sin(phi) * Math.cos(theta),
        radius * Math.cos(phi) * 0.68,
        radius * Math.sin(phi) * Math.sin(theta)
      );
    }
    geometry.setAttribute("position", new THREE.Float32BufferAttribute(points, 3));

    const material = new THREE.PointsMaterial({
      color: 0x8feaff,
      size: 0.12,
      transparent: true,
      opacity: 0.8,
      map: this.textures.gradient,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
    });

    this.scene.add(new THREE.Points(geometry, material));
  }

  createEarthBody() {
    const sphere = new THREE.Mesh(
      new THREE.SphereGeometry(EARTH_RADIUS, 96, 96),
      new THREE.MeshPhongMaterial({
        map: this.textures.earth,
        color: 0x8cd8ff,
        emissive: 0x123e98,
        emissiveIntensity: 0.34,
        shininess: 18,
        transparent: true,
        opacity: 0.98,
      })
    );

    const gridSphere = new THREE.Mesh(
      new THREE.SphereGeometry(EARTH_RADIUS + 0.08, 48, 48),
      new THREE.MeshBasicMaterial({
        color: 0x28d7ff,
        wireframe: true,
        transparent: true,
        opacity: 0.12,
      })
    );

    const atmosphere = new THREE.Mesh(
      new THREE.SphereGeometry(EARTH_RADIUS + 0.28, 64, 64),
      new THREE.MeshBasicMaterial({
        color: 0x2ec7ff,
        transparent: true,
        opacity: 0.07,
        side: THREE.BackSide,
        blending: THREE.AdditiveBlending,
      })
    );

    const glowSprite = new THREE.Sprite(
      new THREE.SpriteMaterial({
        map: this.textures.glow,
        color: 0x3fbfff,
        transparent: true,
        opacity: 0.48,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      })
    );
    glowSprite.scale.set(11, 11, 1);

    this.earthGroup.add(sphere, gridSphere, atmosphere, glowSprite);
  }

  createBackHalo() {
    const halo = new THREE.Sprite(
      new THREE.SpriteMaterial({
        map: this.textures.gradient,
        color: 0x39caff,
        transparent: true,
        opacity: 0.34,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      })
    );
    halo.position.set(0, 0.22, -1.9);
    halo.scale.set(11.2, 11.2, 1);

    const underGlow = new THREE.Mesh(
      new THREE.CircleGeometry(4.8, 64),
      new THREE.MeshBasicMaterial({
        color: 0x1dd9ff,
        transparent: true,
        opacity: 0.1,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      })
    );
    underGlow.rotation.x = -Math.PI / 2.05;
    underGlow.position.set(0, -4.25, 0);

    this.scene.add(halo, underGlow);
  }

  createOrbitRings() {
    const ringMaterial = new THREE.MeshBasicMaterial({
      color: 0x24d8ff,
      transparent: true,
      opacity: 0.16,
      side: THREE.DoubleSide,
    });

    const ring1 = new THREE.Mesh(new THREE.TorusGeometry(EARTH_RADIUS + 0.72, 0.055, 16, 140), ringMaterial);
    ring1.rotation.x = Math.PI / 2.35;
    ring1.rotation.z = Math.PI / 5.5;

    const ring2 = new THREE.Mesh(new THREE.TorusGeometry(EARTH_RADIUS + 0.96, 0.04, 16, 140), ringMaterial.clone());
    ring2.material.opacity = 0.09;
    ring2.rotation.x = Math.PI / 2.75;
    ring2.rotation.y = Math.PI / 4.5;

    this.earthGroup.add(ring1, ring2);
  }

  clearFlows() {
    this.flowGroup.children.slice().forEach((child) => {
      this.flowGroup.remove(child);
    });

    this.markerGroup.children.slice().forEach((child) => {
      this.markerGroup.remove(child);
    });

    this.pulseGroup.children.slice().forEach((child) => {
      this.pulseGroup.remove(child);
    });

    this.animatedFlows = [];
    this.labelAnchors = [];
    this.targetMarker = null;
    if (this.labelsElement) {
      this.labelsElement.innerHTML = "";
    }
  }

  setData(payload) {
    this.clearFlows();

    const target = payload.target || DEFAULT_TARGET;
    const flows = Array.isArray(payload.globe_flows) ? payload.globe_flows.slice(0, 8) : [];

    this.createTargetMarker(target);
    flows.forEach((flow, index) => this.createFlow(flow, target, index));
  }

  createTargetMarker(target) {
    const targetPosition = lonLatToVector3(EARTH_RADIUS + 0.12, Number(target.lng || DEFAULT_TARGET.lng), Number(target.lat || DEFAULT_TARGET.lat));

    const ring = new THREE.Sprite(
      new THREE.SpriteMaterial({
        map: this.textures.aperture,
        color: 0x3cf4ff,
        transparent: true,
        opacity: 0.88,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      })
    );
    ring.position.copy(targetPosition);
    ring.scale.set(0.9, 0.9, 1);

    const glow = new THREE.Sprite(
      new THREE.SpriteMaterial({
        map: this.textures.glow,
        color: 0x23c6ff,
        transparent: true,
        opacity: 0.5,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      })
    );
    glow.position.copy(targetPosition.clone().multiplyScalar(1.02));
    glow.scale.set(1.2, 1.2, 1);

    const column = new THREE.Sprite(
      new THREE.SpriteMaterial({
        map: this.textures.lightColumn,
        color: 0x2af1ff,
        transparent: true,
        opacity: 0.7,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      })
    );
    column.position.copy(targetPosition.clone().multiplyScalar(1.07));
    column.scale.set(0.56, 1.55, 1);

    const beacon = new THREE.Sprite(
      new THREE.SpriteMaterial({
        map: this.textures.redCircle,
        color: 0x8cf5ff,
        transparent: true,
        opacity: 0.84,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      })
    );
    beacon.position.copy(targetPosition.clone().multiplyScalar(1.01));
    beacon.scale.set(0.52, 0.52, 1);

    this.markerGroup.add(ring, glow, column, beacon);
    this.targetMarker = { ring, glow, column, beacon };
  }

  createFlow(flow, target, index) {
    const source = lonLatToVector3(
      EARTH_RADIUS + 0.06,
      Number(flow.source_lng || 0),
      Number(flow.source_lat || 0)
    );
    const destination = lonLatToVector3(
      EARTH_RADIUS + 0.08,
      Number(target.lng || DEFAULT_TARGET.lng),
      Number(target.lat || DEFAULT_TARGET.lat)
    );
    const curve = buildArcCurve(source, destination);
    const color = FLOW_COLORS[flow.severity] || FLOW_COLORS.medium;

    const arcPoints = curve.getPoints(160);
    const line = buildLineGeometry(arcPoints);
    line.material.color.setHex(color);
    line.material.opacity = 0.28 + Math.min(Number(flow.count || 0) / 160, 0.12);

    const innerLine = buildLineGeometry(arcPoints);
    innerLine.material.color.setHex(0xffd89a);
    innerLine.material.opacity = 0.22;
    innerLine.scale.setScalar(0.9995);

    const sourcePulse = new THREE.Sprite(
      new THREE.SpriteMaterial({
        map: this.textures.redCircle,
        color,
        transparent: true,
        opacity: 0.82,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      })
    );
    sourcePulse.position.copy(source);
    sourcePulse.scale.set(0.46, 0.46, 1);

    const sourceHalo = new THREE.Sprite(
      new THREE.SpriteMaterial({
        map: this.textures.aperture,
        color: 0xffcf84,
        transparent: true,
        opacity: 0.48,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      })
    );
    sourceHalo.position.copy(source.clone().multiplyScalar(1.01));
    sourceHalo.scale.set(0.62, 0.62, 1);

    const pulse = new THREE.Mesh(
      new THREE.SphereGeometry(0.052, 12, 12),
      new THREE.MeshBasicMaterial({
        color: 0xfff0c9,
        transparent: true,
        opacity: 0.9,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      })
    );

    const trail = new THREE.Points(
      new THREE.BufferGeometry(),
      new THREE.PointsMaterial({
        color,
        size: 0.09,
        transparent: true,
        opacity: 0.8,
        map: this.textures.gradient,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      })
    );

    this.flowGroup.add(line, innerLine, pulse, trail);
    this.markerGroup.add(sourcePulse, sourceHalo);

    const ripple = new THREE.Mesh(
      new THREE.RingGeometry(0.11, 0.22, 48),
      new THREE.MeshBasicMaterial({
        color,
        transparent: true,
        opacity: 0.42,
        side: THREE.DoubleSide,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
      })
    );
    ripple.position.copy(source.clone().multiplyScalar(1.002));
    ripple.lookAt(new THREE.Vector3(0, 0, 0));
    this.pulseGroup.add(ripple);

    const label = createLabelNode();
    label.innerHTML = `
      <span class="threat-globe__label-head"><i class="threat-globe__flag">${screenFlowBadge(flow)}</i><b>${screenFlowDisplayName(flow)}</b></span>
    `;
    this.labelsElement.appendChild(label);
    this.labelAnchors.push({ element: label, position: source.clone().multiplyScalar(1.14) });

    this.animatedFlows.push({
      curve,
      line,
      innerLine,
      pulse,
      trail,
      halo: sourceHalo,
      ripple,
      offset: Math.random(),
      speed: 0.07 + index * 0.012,
    });
  }

  updateLabels() {
    const width = this.stageElement.clientWidth;
    const height = this.stageElement.clientHeight;

    this.labelAnchors.forEach(({ element, position }) => {
      const projected = this.earthGroup.localToWorld(position.clone()).project(this.camera);
      const visible = projected.z < 1 && projected.z > -1;
      if (!visible) {
        element.hidden = true;
        return;
      }

      const x = ((projected.x + 1) / 2) * width;
      const y = ((-projected.y + 1) / 2) * height;
      if (x < 40 || x > width - 40 || y < 30 || y > height - 30) {
        element.hidden = true;
        return;
      }

      element.hidden = false;
      element.style.left = `${x}px`;
      element.style.top = `${y}px`;
    });
  }

  handleResize() {
    const width = Math.max(this.stageElement.clientWidth, 320);
    const height = Math.max(this.stageElement.clientHeight, 480);
    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(width, height, false);
    this.renderer.domElement.style.width = "100%";
    this.renderer.domElement.style.height = "100%";
  }

  animate(time = performance.now()) {
    this.controls.update();

    this.earthGroup.rotation.y += 0.0008;
    this.earthGroup.rotation.z = Math.sin(time * 0.00018) * 0.012;

    if (this.targetMarker) {
      const pulseScale = 1 + Math.sin(time * 0.0038) * 0.08;
      this.targetMarker.ring.scale.set(0.92 * pulseScale, 0.92 * pulseScale, 1);
      this.targetMarker.glow.material.opacity = 0.42 + (Math.sin(time * 0.0032) + 1) * 0.08;
      this.targetMarker.column.material.opacity = 0.58 + (Math.sin(time * 0.0024) + 1) * 0.06;
      this.targetMarker.beacon.scale.set(0.48 + pulseScale * 0.08, 0.48 + pulseScale * 0.08, 1);
    }

    this.animatedFlows.forEach((item) => {
      const t = (time * 0.00006 * item.speed + item.offset) % 1;
      const point = item.curve.getPointAt(t);
      const shimmer = (Math.sin(time * 0.002 + item.offset * Math.PI * 2) + 1) * 0.5;
      item.line.material.opacity = 0.18 + shimmer * 0.16;
      item.innerLine.material.opacity = 0.12 + shimmer * 0.16;
      item.pulse.position.copy(point);
      const haloScale = 0.58 + (Math.sin(time * 0.002 + item.offset * Math.PI * 2) + 1) * 0.08;
      item.halo.scale.set(haloScale, haloScale, 1);
      const rippleScale = 1 + (Math.sin(time * 0.0026 + item.offset * Math.PI * 2) + 1) * 0.18;
      item.ripple.scale.set(rippleScale, rippleScale, 1);
      item.ripple.material.opacity = 0.16 + (Math.sin(time * 0.0026 + item.offset * Math.PI * 2) + 1) * 0.12;

      const trailSamples = [];
      for (let index = 0; index < 10; index += 1) {
        const sampleT = (t - index * 0.016 + 1) % 1;
        const sample = item.curve.getPointAt(sampleT);
        trailSamples.push(sample.x, sample.y, sample.z);
      }
      item.trail.geometry.setAttribute("position", new THREE.Float32BufferAttribute(trailSamples, 3));
      item.trail.geometry.attributes.position.needsUpdate = true;
    });

    this.updateLabels();
    this.renderer.render(this.scene, this.camera);
    this.frameId = requestAnimationFrame(this.animate);
  }
}

export async function createThreatGlobe(stageElement, labelsElement) {
  const instance = new ThreatEarthScreen(stageElement, labelsElement);
  await instance.init();
  return instance;
}
