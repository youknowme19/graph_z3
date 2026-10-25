import React, { useEffect, useRef, useState, useCallback } from 'react';
import * as THREE from 'three';
import { GLTFLoader } from 'three/examples/jsm/loaders/GLTFLoader.js';
import { ArrowRight, Terminal, Shield, ChevronDown, RotateCcw } from 'lucide-react';
import { BRAND } from '../config/brand';
import { useTheme } from '../context/ThemeContext';
import { createLaptopModel } from './LaptopModel3D';
import { createMaskSculpturalGeometry } from './MaskSculpturalGeometry';

interface HeroCinematic3DProps {
  onStartAnalysis: () => void;
  onExploreDemo: () => void;
}

export const HeroCinematic3D: React.FC<HeroCinematic3DProps> = ({
  onStartAnalysis,
  onExploreDemo,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const { theme } = useTheme();
  const themeRef = useRef(theme);
  useEffect(() => {
    themeRef.current = theme;
  }, [theme]);

  // Prevent browser scroll restoration from skipping the opening intro
  useEffect(() => {
    if ('scrollRestoration' in window.history) {
      window.history.scrollRestoration = 'manual';
    }
    window.scrollTo(0, 0);
  }, []);

  // Loading state
  const [loadingProgress, setLoadingProgress] = useState<number>(0);
  const [isLoaded, setIsLoaded] = useState<boolean>(false);
  const [hasWebGL, setHasWebGL] = useState<boolean>(true);

  // Intro Animation State ('loading' -> 'floating' -> 'transitioning' -> 'entered')
  const [introState, setIntroState] = useState<'loading' | 'floating' | 'transitioning' | 'entered'>('loading');

  const handleEnter = useCallback(() => {
    setIntroState((prev) => {
      if (prev === 'entered' || prev === 'transitioning') return prev;
      setTimeout(() => {
        setIntroState('entered');
      }, 750);
      return 'transitioning';
    });
  }, []);

  // Story scroll progress (0.00 -> 1.00)
  const [scrollProgress, setScrollProgress] = useState<number>(0);

  // Auto-enter timer: after 3.2s of floating glory, transition into the website automatically
  useEffect(() => {
    if (isLoaded && introState === 'floating') {
      const timer = setTimeout(() => {
        handleEnter();
      }, 3200);
      return () => clearTimeout(timer);
    }
  }, [isLoaded, introState, handleEnter]);

  // Dynamic code canvas generator for mask texture
  const codeCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const codeTextureRef = useRef<THREE.CanvasTexture | null>(null);

  // Init Dynamic Code Canvas with high-resolution texture
  const initCodeCanvas = useCallback(() => {
    const canvas = document.createElement('canvas');
    canvas.width = 1024;
    canvas.height = 1024;
    const ctx = canvas.getContext('2d');
    if (!ctx) return null;

    codeCanvasRef.current = canvas;
    const texture = new THREE.CanvasTexture(canvas);
    texture.wrapS = THREE.RepeatWrapping;
    texture.wrapT = THREE.RepeatWrapping;
    codeTextureRef.current = texture;

    return { canvas, ctx, texture };
  }, []);

  useEffect(() => {
    // Check WebGL availability
    try {
      const testCanvas = document.createElement('canvas');
      const gl = testCanvas.getContext('webgl') || testCanvas.getContext('experimental-webgl');
      if (!gl) {
        setHasWebGL(false);
        setIsLoaded(true);
        return;
      }
    } catch {
      setHasWebGL(false);
      setIsLoaded(true);
      return;
    }

    const container = containerRef.current;
    const canvas = canvasRef.current;
    if (!container || !canvas) return;

    let width = container.clientWidth;
    let height = container.clientHeight;

    // Three.js Scene Setup
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(40, width / height, 0.1, 100);
    camera.position.set(0, 0, 6.5);

    const renderer = new THREE.WebGLRenderer({
      canvas,
      antialias: true,
      alpha: true,
      powerPreference: 'high-performance',
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.3;

    // Lighting Setup
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.7);
    scene.add(ambientLight);

    // Dramatic Crimson Rim Light from rear right
    const crimsonRimRight = new THREE.DirectionalLight(0xf0273f, 5.5);
    crimsonRimRight.position.set(4.5, 3.0, -2.5);
    scene.add(crimsonRimRight);

    // Crimson Rim Light from rear left
    const crimsonRimLeft = new THREE.DirectionalLight(0xf0273f, 4.0);
    crimsonRimLeft.position.set(-4.5, 2.0, -2.0);
    scene.add(crimsonRimLeft);

    // Front Controlled Key Light (White highlight)
    const frontKeyLight = new THREE.DirectionalLight(0xffffff, 1.8);
    frontKeyLight.position.set(-1.5, 2.5, 5.5);
    scene.add(frontKeyLight);

    // Moving dynamic point light for mask laser scan
    const maskSweepLight = new THREE.PointLight(0xff354b, 4.5, 8);
    maskSweepLight.position.set(0, 0, 2.5);
    scene.add(maskSweepLight);

    // Groups for Transforms
    const hackerGroup = new THREE.Group();
    const maskGroup = new THREE.Group();
    const geometricGroup = new THREE.Group();

    scene.add(hackerGroup);
    scene.add(maskGroup);
    scene.add(geometricGroup);

    // Build Monumental Floating 3D Laptop with Custom PBR Materials
    const laptopModel = createLaptopModel(scene, () => {
      setIsLoaded(true);
      setIntroState((prev) => (prev === 'loading' ? 'floating' : prev));
    });

    // Build Bespoke Sculptural Geometry for the Mask Sequence (replacing generic node-web)
    const maskSculpture = createMaskSculpturalGeometry();
    maskSculpture.group.visible = false;
    scene.add(maskSculpture.group);

    // Architectural perspective grid that expands into the incoming workbench chassis
    const gridHelper = new THREE.GridHelper(22, 32, 0xf0273f, 0x440c18);
    gridHelper.position.set(0, -1.6, 0);
    geometricGroup.add(gridHelper);

    geometricGroup.visible = false;
    geometricGroup.scale.set(0.01, 0.01, 0.01);

    // Initial transforms
    // Scene 1 starts with models hidden
    hackerGroup.position.set(0, -0.3, 1.6);
    hackerGroup.scale.set(0.01, 0.01, 0.01);
    hackerGroup.visible = false;

    maskGroup.position.set(0, 0, 2.2);
    maskGroup.scale.set(0.01, 0.01, 0.01);
    maskGroup.visible = false;

    // Setup Code Canvas Texture
    const codeCanvasObj = initCodeCanvas();

    // Load Models using GLTFLoader
    const loader = new GLTFLoader();
    let loadedCount = 0;
    const totalModels = 2;

    const checkAllLoaded = () => {
      loadedCount++;
      setLoadingProgress(Math.round((loadedCount / totalModels) * 100));
      if (loadedCount >= totalModels) {
        setIsLoaded(true);
      }
    };

    // Load Hacker Body
    loader.load(
      '/models/hacker_body.glb',
      (gltf) => {
        const model = gltf.scene;

        // Apply tactical stealth material with crimson rim reactivity
        // Preserve original textures while setting roughness & metalness
        model.traverse((child) => {
          if ((child as THREE.Mesh).isMesh) {
            const mesh = child as THREE.Mesh;
            mesh.castShadow = true;
            mesh.receiveShadow = true;
            if (mesh.material) {
              const mat = mesh.material as THREE.MeshStandardMaterial;
              mat.roughness = 0.45;
              mat.metalness = 0.25;
              mat.color = new THREE.Color(0xd0d0d8);
            }
          }
        });

        // Center model inside hackerGroup
        const box = new THREE.Box3().setFromObject(model);
        const center = box.getCenter(new THREE.Vector3());
        model.position.sub(center);

        hackerGroup.add(model);
        checkAllLoaded();
      },
      (xhr) => {
        if (xhr.total > 0) {
          const p = Math.round((xhr.loaded / xhr.total) * 50);
          setLoadingProgress(p);
        }
      },
      (err) => {
        console.warn('Failed to load hacker_body.glb', err);
        checkAllLoaded();
      }
    );

    // Load Standalone White Mask
    loader.load(
      '/models/mask.glb',
      (gltf) => {
        const model = gltf.scene;

        // Apply white porcelain hacker mask material with dynamic code overlay
        // Compute bounding box and generate planar UV projection attributes
        // so the code texture maps seamlessly onto the front surface of the mask!
        model.traverse((child) => {
          if ((child as THREE.Mesh).isMesh) {
            const mesh = child as THREE.Mesh;
            const geom = mesh.geometry;

            if (geom) {
              geom.computeBoundingBox();
              const bbox = geom.boundingBox;
              if (bbox && !geom.attributes.uv) {
                const pos = geom.attributes.position;
                const count = pos.count;
                const uvs = new Float32Array(count * 2);
                const widthRange = bbox.max.x - bbox.min.x || 1;
                const heightRange = bbox.max.y - bbox.min.y || 1;

                for (let i = 0; i < count; i++) {
                  const x = pos.getX(i);
                  const y = pos.getY(i);
                  // Planar front-projection UV mapping
                  uvs[i * 2] = (x - bbox.min.x) / widthRange;
                  uvs[i * 2 + 1] = (y - bbox.min.y) / heightRange;
                }
                geom.setAttribute('uv', new THREE.BufferAttribute(uvs, 2));
              }
            }

            // White porcelain material with dynamic code projection
            const customMaterial = new THREE.MeshStandardMaterial({
              color: 0xffffff,
              roughness: 0.22,
              metalness: 0.04,
              map: codeTextureRef.current || null,
              emissive: 0x300508,
              emissiveIntensity: 0.25,
            });

            mesh.material = customMaterial;
            mesh.castShadow = true;
            mesh.receiveShadow = true;
          }
        });

        // Center mask inside maskGroup
        const box = new THREE.Box3().setFromObject(model);
        const center = box.getCenter(new THREE.Vector3());
        model.position.sub(center);

        maskGroup.add(model);
        checkAllLoaded();
      },
      (xhr) => {
        if (xhr.total > 0) {
          const p = 50 + Math.round((xhr.loaded / xhr.total) * 50);
          setLoadingProgress(p);
        }
      },
      (err) => {
        console.warn('Failed to load mask.glb', err);
        checkAllLoaded();
      }
    );

    // Mouse Parallax
    let mouseX = 0;
    let mouseY = 0;
    let targetMouseX = 0;
    let targetMouseY = 0;

    const handleMouseMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      const x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      const y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
      targetMouseX = x * 0.3;
      targetMouseY = y * 0.2;
    };

    window.addEventListener('mousemove', handleMouseMove);

    // Scroll-Linked Animation Logic
    let currentScrollProgress = 0;
    let targetScrollProgress = 0;

    const handleScroll = () => {
      const parent = container.parentElement;
      if (!parent) return;

      const parentTop = parent.offsetTop;
      const scrollDist = parent.offsetHeight - window.innerHeight;
      if (scrollDist <= 0) return;

      const progress = Math.max(0, Math.min(1, (window.scrollY - parentTop) / scrollDist));
      targetScrollProgress = progress;
      setScrollProgress(progress);
      if (progress > 0.01) {
        handleEnter();
      }
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();

    // Code Stream Data for Mask Surface Animation
    const codeSnippets = [
      '0x7F454C46 · ELF64',
      'claripy.BVS("sym_buf", 256)',
      '(check-sat) -> SAT',
      'SageConv(40_DIM) [0.942]',
      '0x10000051c : STRNCPY_CHK',
      'UNSAT: BOUNDS_GUARDED',
      'Z3_SOLVER_MODEL_EXTRACT',
      'STACK_CANARY_CORRUPTED',
      'VEX_IR_LIFT: t0 = GET:I64',
      '0x4141414141414141',
      '(assert (bvugt copy_size 0x20))',
      'MEMCPY_BOUNDS_CHECK_FAIL',
      'PRUNED_PATHS: 99.66%',
      'SYNTHESIZED_REPRODUCER: 40B',
      'INVARIANT_VIOLATION_CONFIRMED',
    ];

    let codeOffset = 0;

    // Render / Animation Loop
    let animationFrameId: number;
    const clock = new THREE.Clock();

    const animate = () => {
      const elapsedTime = clock.getElapsedTime();

      // Smooth mouse interpolation
      mouseX += (targetMouseX - mouseX) * 0.05;
      mouseY += (targetMouseY - mouseY) * 0.05;

      // Smooth scroll interpolation
      currentScrollProgress += (targetScrollProgress - currentScrollProgress) * 0.08;
      const p = currentScrollProgress;

      // Draw Animated Code onto Mask Texture Canvas
      if (codeCanvasObj && codeCanvasObj.ctx) {
        const { ctx, canvas } = codeCanvasObj;

        // Base white porcelain background
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        // Subtle shaded contours
        const grad = ctx.createLinearGradient(0, 0, canvas.width, canvas.height);
        grad.addColorStop(0, 'rgba(12, 14, 20, 0.04)');
        grad.addColorStop(0.5, 'rgba(240, 39, 63, 0.09)');
        grad.addColorStop(1, 'rgba(12, 14, 20, 0.04)');
        ctx.fillStyle = grad;
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        // Dark eye contours on the texture to emphasize depth
        ctx.fillStyle = 'rgba(10, 10, 14, 0.85)';
        // Left eye
        ctx.beginPath();
        ctx.ellipse(360, 420, 95, 45, -0.15, 0, Math.PI * 2);
        ctx.fill();
        // Right eye
        ctx.beginPath();
        ctx.ellipse(664, 420, 95, 45, 0.15, 0, Math.PI * 2);
        ctx.fill();

        // Streaming Crimson & Pitch Black Technical Code Lines
        codeOffset += 1.4 + p * 2.2;
        if (codeOffset > 60) codeOffset = 0;

        ctx.font = 'bold 26px "JetBrains Mono", monospace';

        for (let row = 0; row < 20; row++) {
          const y = (row * 50 + codeOffset) % canvas.height;
          // Deep eye sockets stay dark
          const isEyeZone = y > 360 && y < 480;
          const snippet = codeSnippets[(row + Math.floor(elapsedTime * 1.5)) % codeSnippets.length];

          // Alternate between high-contrast crimson and pitch black typography
          if (row % 2 === 0) {
            ctx.fillStyle = '#f0273f';
            ctx.globalAlpha = isEyeZone ? 0.35 : 0.95;
          } else {
            ctx.fillStyle = '#0a0a0d';
            ctx.globalAlpha = isEyeZone ? 0.30 : 0.90;
          }

          const xOffset = 50 + ((row * 47) % 130);
          ctx.fillText(snippet, xOffset, y);

          // Right column hex address stamp
          ctx.fillStyle = '#f0273f';
          ctx.globalAlpha = 0.85;
          ctx.fillText(`0x${(0x1000004ac + row * 0x64).toString(16)}`, 660, y);
        }

        // Sweeping horizontal laser scan bar
        const scanY = (elapsedTime * 260 + p * 600) % canvas.height;
        ctx.globalAlpha = 0.95;
        ctx.fillStyle = '#ff2b44';
        ctx.fillRect(0, scanY, canvas.width, 4);

        // Laser scan glow
        const scanGlow = ctx.createLinearGradient(0, scanY - 25, 0, scanY + 25);
        scanGlow.addColorStop(0, 'rgba(240, 39, 63, 0)');
        scanGlow.addColorStop(0.5, 'rgba(255, 43, 68, 0.45)');
        scanGlow.addColorStop(1, 'rgba(240, 39, 63, 0)');
        ctx.fillStyle = scanGlow;
        ctx.fillRect(0, scanY - 25, canvas.width, 50);

        ctx.globalAlpha = 1.0;

        if (codeTextureRef.current) {
          codeTextureRef.current.needsUpdate = true;
        }
      }

      // Laptop Model Animation & Scroll Update
      laptopModel.update(elapsedTime, p, mouseX, mouseY, themeRef.current === 'dark');

      // Camera Breathing, Parallax & Dynamic Push
      if (p < 0.10) {
        camera.position.x = mouseX * 0.25;
        camera.position.y = mouseY * 0.20;
        camera.position.z = 6.6;
      } else if (p >= 0.10 && p < 0.20) {
        const tCam = (p - 0.10) / 0.10;
        camera.position.x = mouseX * 0.25;
        camera.position.y = mouseY * 0.20;
        camera.position.z = THREE.MathUtils.lerp(6.6, 5.8, tCam);
      } else if (p >= 0.20 && p < 0.32) {
        const tCam = (p - 0.20) / 0.12;
        camera.position.x = mouseX * 0.30;
        camera.position.y = mouseY * 0.22;
        camera.position.z = THREE.MathUtils.lerp(5.8, 5.0, tCam);
      } else if (p >= 0.32 && p < 0.46) {
        const tCam = (p - 0.32) / 0.14;
        camera.position.x = mouseX * 0.35;
        camera.position.y = mouseY * 0.25;
        camera.position.z = THREE.MathUtils.lerp(5.0, 6.5, tCam);
      } else {
        camera.position.x = mouseX * 0.45;
        camera.position.y = mouseY * 0.35;
        camera.position.z = 6.5;
      }
      camera.lookAt(0, 0, 0);

      // Studio Lighting Coordination across Phases
      if (p < 0.32) {
        // Pure studio white environment
        ambientLight.intensity = 1.4;
        crimsonRimRight.intensity = 0.4;
        crimsonRimLeft.intensity = 0.4;
        frontKeyLight.intensity = 2.0;
      } else if (p >= 0.32 && p < 0.46) {
        // Phase D & E: Crimson emergence & shift to cinematic black
        const tLight = (p - 0.32) / 0.14;
        ambientLight.intensity = THREE.MathUtils.lerp(1.4, 0.7, tLight);
        crimsonRimRight.intensity = THREE.MathUtils.lerp(0.4, 5.5, tLight);
        crimsonRimLeft.intensity = THREE.MathUtils.lerp(0.4, 4.0, tLight);
        frontKeyLight.intensity = THREE.MathUtils.lerp(2.0, 1.8, tLight);
      } else if (p >= 0.46 && p < 0.88) {
        // Hacker & Mask cinematic dark environment
        ambientLight.intensity = 0.7;
        crimsonRimRight.intensity = 5.5;
        crimsonRimLeft.intensity = 4.0;
        frontKeyLight.intensity = 1.8;
      }

      // =========================================================================
      // SCROLL CHOREOGRAPHY (p: 0.00 -> 1.00)
      // =========================================================================

      // Initial Hero Sculpture Phase (0.00 <= p < 0.46):
      // Hacker and subsequent models hidden while sculpture is active
      if (p < 0.46) {
        hackerGroup.visible = false;
        maskGroup.visible = false;
        geometricGroup.visible = false;
        maskSculpture.group.visible = false;
      }
      // Scene 2 (0.46 <= p < 0.60):
      // Transition to black. Reveal hacker_body as monumental subject!
      else if (p >= 0.46 && p < 0.60) {
        hackerGroup.visible = true;
        maskGroup.visible = false;
        geometricGroup.visible = false;
        maskSculpture.group.visible = false;

        const t = (p - 0.46) / 0.14; // 0 -> 1
        // Hacker emerges front-and-center, monumental size
        hackerGroup.position.x = 0;
        hackerGroup.position.y = THREE.MathUtils.lerp(-0.6, -0.35, t);
        hackerGroup.position.z = THREE.MathUtils.lerp(0.5, 1.8, t);

        // Monumental close-up scale
        const scaleVal = THREE.MathUtils.lerp(1.5, 3.0, t);
        hackerGroup.scale.set(scaleVal, scaleVal, scaleVal);

        hackerGroup.rotation.y = mouseX * 0.2;
        hackerGroup.rotation.x = mouseY * 0.1;
      }
      // Scene 3 (0.60 <= p < 0.76):
      // Hacker moves to the right, scale adjusts, space opens on left for typography
      else if (p >= 0.60 && p < 0.76) {
        hackerGroup.visible = true;
        maskGroup.visible = false;
        geometricGroup.visible = false;
        maskSculpture.group.visible = false;

        const t = (p - 0.60) / 0.16; // 0 -> 1
        // Smooth slide from center (0) to right (1.85)
        hackerGroup.position.x = THREE.MathUtils.lerp(0.0, 1.85, t);
        hackerGroup.position.y = THREE.MathUtils.lerp(-0.35, -0.4, t);
        hackerGroup.position.z = THREE.MathUtils.lerp(1.8, 0.6, t);

        // Adjust scale from monumental close-up to balanced full figure
        const scaleVal = THREE.MathUtils.lerp(3.0, 2.2, t);
        hackerGroup.scale.set(scaleVal, scaleVal, scaleVal);

        // Subtle stance rotation facing inward toward center
        hackerGroup.rotation.y = THREE.MathUtils.lerp(0.0, -0.35, t) + mouseX * 0.2;
        hackerGroup.rotation.x = mouseY * 0.1;
      }
      // Scene 4 & 5 (0.76 <= p < 0.90):
      // Hacker recedes into shadow. Standalone white mask becomes central subject.
      // Choreographed zoom-out, crimson contour splines & architectural geometry reveal.
      else if (p >= 0.76 && p < 0.90) {
        hackerGroup.visible = false;
        maskGroup.visible = true;
        geometricGroup.visible = false;
        maskSculpture.group.visible = true;

        const isMobile = camera.aspect < 1.0;

        // Phase 1 (0.76 <= p < 0.79): Mask begins large, commanding & centered
        // Phase 2 (0.79 <= p < 0.90): Mask slowly recedes as camera pulls back,
        // reveals 3D contours with white highlights & crimson reflections,
        // and transitions slightly right to frame the dimensional typography.
        if (p < 0.79) {
          const tIntro = (p - 0.76) / 0.03;
          maskGroup.position.set(0, isMobile ? 0.15 : 0.05, THREE.MathUtils.lerp(2.0, 2.35, tIntro));
          const maskScale = isMobile
            ? THREE.MathUtils.lerp(1.6, 1.85, tIntro)
            : THREE.MathUtils.lerp(2.0, 2.35, tIntro);
          maskGroup.scale.setScalar(maskScale);

          maskGroup.rotation.y = mouseX * 0.25;
          maskGroup.rotation.x = -0.06 - mouseY * 0.15;
          maskGroup.rotation.z = Math.sin(elapsedTime * 1.0) * 0.015;

          maskSweepLight.intensity = THREE.MathUtils.lerp(3.5, 5.0, tIntro);
          maskSweepLight.position.set(
            Math.sin(elapsedTime * 2.2) * 1.5,
            Math.cos(elapsedTime * 1.8) * 1.0,
            maskGroup.position.z + 1.2
          );

          maskSculpture.group.position.copy(maskGroup.position);
          maskSculpture.group.rotation.copy(maskGroup.rotation);
          maskSculpture.update(p, elapsedTime, mouseX, mouseY);
        } else {
          const t = (p - 0.79) / 0.11; // 0 -> 1

          // Camera & mask zoom-out: Mask recedes gracefully without becoming tiny
          maskGroup.position.x = isMobile ? 0 : THREE.MathUtils.lerp(0.0, 1.35, t);
          maskGroup.position.y = isMobile
            ? THREE.MathUtils.lerp(0.15, 0.42, t)
            : THREE.MathUtils.lerp(0.05, 0.02, t);
          maskGroup.position.z = isMobile
            ? THREE.MathUtils.lerp(2.2, 1.35, t)
            : THREE.MathUtils.lerp(2.35, 1.30, t);

          // Controlled scale: stays visually dominant and significant
          const maskScale = isMobile
            ? THREE.MathUtils.lerp(1.85, 1.2, t)
            : THREE.MathUtils.lerp(2.35, 1.55, t);
          maskGroup.scale.setScalar(maskScale);

          // Subtle 3D rotation reveals contours, cheekbone curves, and porcelain depth
          maskGroup.rotation.y = THREE.MathUtils.lerp(0.0, -0.30, t) + mouseX * 0.25;
          maskGroup.rotation.x = THREE.MathUtils.lerp(-0.06, 0.08, t) - mouseY * 0.18;
          maskGroup.rotation.z = THREE.MathUtils.lerp(0.0, -0.03, t) + Math.sin(elapsedTime * 1.2) * 0.015;

          // Mask sweep light tracks facial contours with controlled highlights
          maskSweepLight.position.set(
            maskGroup.position.x + Math.sin(elapsedTime * 2.0) * 1.4,
            maskGroup.position.y + Math.cos(elapsedTime * 1.8) * 1.0,
            maskGroup.position.z + 1.2
          );
          maskSweepLight.intensity = THREE.MathUtils.lerp(5.0, 3.8, t);

          // Update Sculptural Geometry anchored to mask
          maskSculpture.group.position.copy(maskGroup.position);
          maskSculpture.group.rotation.copy(maskGroup.rotation);
          maskSculpture.update(p, elapsedTime, mouseX, mouseY);
        }
      }
      // Scene 6 & The Transformational Bridge into the Operational Workbench (0.90 <= p <= 1.00):
      else {
        hackerGroup.visible = false;
        geometricGroup.visible = true;

        const isMobile = camera.aspect < 1.0;
        const t = Math.max(0, Math.min(1, (p - 0.90) / 0.10)); // 0 -> 1

        // 1. Mask gently recedes into depth as workbench chassis emerges
        if (t < 0.85) {
          maskGroup.visible = true;
          maskGroup.position.x = isMobile ? 0 : THREE.MathUtils.lerp(1.35, 0.9, t);
          maskGroup.position.y = isMobile
            ? THREE.MathUtils.lerp(0.42, 0.1, t)
            : THREE.MathUtils.lerp(0.02, -0.35, t);
          maskGroup.position.z = THREE.MathUtils.lerp(1.30, -1.0, t);
          maskGroup.scale.setScalar(isMobile ? THREE.MathUtils.lerp(1.2, 0.6, t) : THREE.MathUtils.lerp(1.55, 0.80, t));
          maskGroup.rotation.y = -0.30 + mouseX * 0.25 + t * 0.2;
          maskSweepLight.intensity = THREE.MathUtils.lerp(3.8, 0.0, t);

          maskSculpture.group.position.copy(maskGroup.position);
          maskSculpture.group.rotation.copy(maskGroup.rotation);
          maskSculpture.update(p, elapsedTime, mouseX, mouseY);
        } else {
          maskGroup.visible = false;
          maskSculpture.group.visible = false;
        }

        // 2. Perspective ground grid expands into the incoming workbench
        geometricGroup.position.set(0, THREE.MathUtils.lerp(-1.0, -1.6, t), THREE.MathUtils.lerp(1.0, 0.0, t));
        const geoScale = THREE.MathUtils.lerp(0.8, 1.4, t);
        geometricGroup.scale.set(geoScale, geoScale, geoScale);
        geometricGroup.rotation.y = elapsedTime * 0.1 + t * 0.5;

        // 3. Lighting adapts synchronously to the incoming workbench environment
        if (themeRef.current === 'light') {
          ambientLight.intensity = THREE.MathUtils.lerp(0.7, 2.0, t);
          crimsonRimRight.intensity = THREE.MathUtils.lerp(5.5, 1.0, t);
          crimsonRimLeft.intensity = THREE.MathUtils.lerp(4.0, 0.6, t);
          frontKeyLight.intensity = THREE.MathUtils.lerp(1.8, 0.8, t);
        } else {
          ambientLight.intensity = THREE.MathUtils.lerp(0.7, 0.95, t);
          crimsonRimRight.intensity = THREE.MathUtils.lerp(5.5, 2.2, t);
          crimsonRimLeft.intensity = THREE.MathUtils.lerp(4.0, 1.6, t);
        }
      }

      renderer.render(scene, camera);
      animationFrameId = requestAnimationFrame(animate);
    };

    animate();

    // Resize Handler
    const handleResize = () => {
      if (!container) return;
      width = container.clientWidth;
      height = container.clientHeight;
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('scroll', handleScroll);
      window.removeEventListener('resize', handleResize);
      laptopModel.dispose();
      maskSculpture.dispose();
      renderer.dispose();
    };
  }, [initCodeCanvas]);

  // Dynamic background color interpolation across all scroll stages:
  // Light Theme:
  //   p < 0.32: Pristine gallery white (#ffffff)
  //   0.32 <= p < 0.46: Smoothly transitions from #ffffff to #07080b
  //   0.46 <= p < 0.88: Cinematic black (#07080b)
  //   0.88 <= p <= 1.00: Physical Transform into the Operational Workbench palette (#f8f9fa)
  // Dark Theme:
  //   p < 0.88: Deep obsidian black (#07080b) throughout hero and cinematic sequences
  //   0.88 <= p <= 1.00: Dark Operational Workbench palette (#07080b)
  const getContainerBg = (p: number, currentTheme: string) => {
    if (currentTheme === 'dark') {
      return '#07080b';
    }
    // Light Theme
    if (p < 0.32) {
      return '#ffffff';
    }
    if (p >= 0.32 && p < 0.46) {
      const t = (p - 0.32) / 0.14;
      const r = Math.round(255 * (1 - t) + 7 * t);
      const g = Math.round(255 * (1 - t) + 8 * t);
      const b = Math.round(255 * (1 - t) + 11 * t);
      return `rgb(${r}, ${g}, ${b})`;
    }
    if (p >= 0.46 && p < 0.88) {
      return '#07080b';
    }
    const t = Math.max(0, Math.min(1, (p - 0.90) / 0.10));
    const r = Math.round(7 * (1 - t) + 248 * t);
    const g = Math.round(8 * (1 - t) + 249 * t);
    const b = Math.round(11 * (1 - t) + 250 * t);
    return `rgb(${r}, ${g}, ${b})`;
  };

  const bgDarkness =
    theme === 'dark'
      ? Math.max(0.65, Math.min(1, 0.65 + (scrollProgress / 0.46) * 0.35))
      : Math.max(0, Math.min(1, (scrollProgress - 0.32) / 0.14));
  const bridgeProgress = Math.max(0, Math.min(1, (scrollProgress - 0.90) / 0.10));
  const containerBgColor = getContainerBg(scrollProgress, theme);

  return (
    <div className="relative w-full h-[520vh] bg-transparent">
      {/* Pinned Viewport Container */}
      <div
        ref={containerRef}
        className="sticky top-0 h-screen w-full overflow-hidden select-none transition-colors duration-150"
        style={{
          backgroundColor: containerBgColor,
        }}
      >
        {/* Subtle radial crimson highlight when dark */}
        <div
          className="absolute inset-0 pointer-events-none z-0 transition-opacity duration-700"
          style={{
            opacity: bgDarkness * (1 - bridgeProgress * 0.4),
            background:
              'radial-gradient(circle at 68% 48%, rgba(240, 39, 63, 0.18) 0%, rgba(7, 8, 11, 0.95) 75%)',
          }}
        />

        {/* Technical Grid Overlay */}
        <div
          className="absolute inset-0 pointer-events-none tech-grid z-0 transition-opacity duration-500"
          style={{ opacity: bgDarkness * 0.04 * (1 - bridgeProgress) + bridgeProgress * 0.03 }}
          aria-hidden
        />

        {/* WebGL 3D Canvas */}
        {hasWebGL ? (
          <canvas
            ref={canvasRef}
            className="absolute inset-0 h-full w-full z-10 block"
          />
        ) : (
          /* High-Tech Fallback if WebGL is unavailable */
          <div className="absolute inset-0 flex items-center justify-center z-10 pointer-events-none">
            <div className="text-center space-y-4 max-w-md p-6 rounded-2xl border border-border bg-surface/90 backdrop-blur-md">
              <Shield className="h-14 w-14 text-rose-500 mx-auto animate-pulse" />
              <h3 className="font-mono text-sm text-primary font-bold uppercase tracking-wider">
                VANTA Autonomous Security Core
              </h3>
              <p className="text-xs text-secondary">
                Hardware accelerated 3D pipeline suspended. Full binary analysis engine operational below.
              </p>
            </div>
          </div>
        )}

        {/* Loading Overlay */}
        {!isLoaded && (
          <div className="absolute inset-0 z-50 flex flex-col items-center justify-center bg-[#07080b] text-white">
            <div className="space-y-4 text-center">
              <div className="inline-flex items-center gap-2">
                <span className="flex h-3 w-3 rounded-full bg-rose-500 animate-ping" />
                <span className="font-mono text-2xl font-black tracking-[0.25em] text-white">
                  {BRAND.wordmark}
                </span>
              </div>
              <p className="font-mono text-xs uppercase tracking-widest text-zinc-400">
                Initializing 3D Assets…
              </p>
              <div className="w-56 h-1 rounded-full bg-zinc-900 overflow-hidden mx-auto border border-zinc-800">
                <div
                  className="h-full bg-rose-500 transition-all duration-200"
                  style={{ width: `${loadingProgress}%` }}
                />
              </div>
              <span className="font-mono text-[10px] text-zinc-500 block">
                {loadingProgress}% Models Streamed
              </span>
            </div>
          </div>
        )}

        {/* Intro Overlay during Floating Phase */}
        {isLoaded && (introState === 'floating' || introState === 'transitioning') && (
          <div
            onClick={handleEnter}
            className={`absolute inset-0 z-30 flex flex-col justify-between items-center py-10 px-6 cursor-pointer select-none transition-all duration-700 ease-out ${
              introState === 'transitioning'
                ? 'opacity-0 scale-110 pointer-events-none'
                : 'opacity-100 scale-100'
            }`}
          >
            {/* Top Brand Pill */}
            <div className="inline-flex items-center gap-2.5 px-4 py-2 rounded-full bg-[#0d0e14]/90 border border-rose-500/30 backdrop-blur-md shadow-2xl transition-transform hover:scale-105">
              <span className="h-2 w-2 rounded-full bg-rose-500 animate-pulse" />
              <span className="font-mono text-xs uppercase tracking-[0.25em] text-zinc-200 font-bold">
                {BRAND.name} // NEURO-SYMBOLIC SECURITY SUITE
              </span>
            </div>

            {/* Bottom Callout & Enter Button */}
            <div className="flex flex-col items-center gap-3.5 text-center pointer-events-auto">
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  handleEnter();
                }}
                className="btn-signal group !py-3.5 !px-8 text-sm sm:text-base font-semibold shadow-2xl shadow-rose-950/70 flex items-center gap-2.5 rounded-xl border border-rose-400/40"
              >
                <span>Enter System</span>
                <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
              </button>
              <div className="flex items-center gap-2 text-xs font-mono text-zinc-400/90 tracking-wider">
                <span>click anywhere or scroll to explore</span>
                <ChevronDown className="h-3.5 w-3.5 text-rose-500 animate-bounce" />
              </div>
            </div>
          </div>
        )}

        {/* =========================================================================
            SCENE 1: Typography Pops Out from Inside the 3D Animation
            Headline: “IS YOUR CODE PROTECTED FROM EVERY HACKER?”
            ========================================================================= */}
        <div
          className={`absolute inset-0 z-20 flex flex-col items-center justify-center px-6 sm:px-12 text-center transition-all duration-700 ease-out pointer-events-none ${
            (introState === 'entered' || introState === 'transitioning') && scrollProgress < 0.14
              ? 'opacity-100 translate-y-0 scale-100'
              : 'opacity-0 translate-y-8 scale-90'
          }`}
        >
          <div className="max-w-5xl space-y-6">
            {/* Main Editorial Headline */}
            <h1
              className={`text-4xl sm:text-6xl md:text-7xl lg:text-8xl font-black tracking-tight uppercase leading-[0.96] transition-colors duration-300 ${
                theme === 'dark' ? 'text-[#f5f5f7]' : 'text-[#090a0f]'
              }`}
            >
              IS YOUR CODE PROTECTED FROM EVERY HACKER?
            </h1>

            <p
              className={`text-sm sm:text-base md:text-lg max-w-2xl mx-auto font-sans font-medium leading-relaxed transition-colors duration-300 ${
                theme === 'dark' ? 'text-[#a2a6b1]' : 'text-[#555a66]'
              }`}
            >
              Explore whether your software withstands mathematical verification before the first exploit compiles.
            </p>

            {/* Scroll Indicator & Replay Trigger */}
            <div className="pt-8 flex flex-col items-center justify-center gap-3">
              <div
                className={`flex flex-col items-center justify-center gap-2 font-mono text-xs uppercase tracking-widest transition-colors duration-300 ${
                  theme === 'dark' ? 'text-[#858b99]' : 'text-[#717684]'
                }`}
              >
                <span>Scroll to explore</span>
                <ChevronDown className="h-4 w-4 text-[#f0273f] animate-bounce" />
              </div>

              <button
                type="button"
                onClick={() => {
                  window.scrollTo({ top: 0, behavior: 'smooth' });
                  setIntroState('floating');
                }}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full bg-zinc-900/70 hover:bg-zinc-800/90 border border-zinc-800/80 text-[11px] font-mono text-zinc-400 hover:text-white transition-all pointer-events-auto cursor-pointer shadow-lg"
              >
                <RotateCcw className="h-3 w-3 text-rose-500" />
                <span>Replay 3D Intro</span>
              </button>
            </div>
          </div>
        </div>

        {/* =========================================================================
            SCENE 2: Monumental Hacker Title Cue
            Appears as the dark atmosphere engulfs the screen (0.46 <= p < 0.60)
            ========================================================================= */}
        <div
          className={`absolute inset-0 z-20 flex flex-col justify-end pb-20 pointer-events-none transition-all duration-700 ${scrollProgress >= 0.46 && scrollProgress < 0.60
            ? 'opacity-100 translate-y-0'
            : 'opacity-0 translate-y-8'
            }`}
        >
          <div className="mx-auto max-w-4xl text-center px-6 space-y-2">
            <h2 className="text-2xl sm:text-4xl font-black text-white uppercase tracking-tight">
              Deconstructing The Attack Surface
            </h2>
          </div>
        </div>

        {/* =========================================================================
            SCENE 3: Editorial Content (Left Grid Column) & Hacker at Right
            (0.60 <= p < 0.76)
            ========================================================================= */}
        <div
          className={`absolute inset-0 z-20 flex items-center transition-all duration-700 pointer-events-none ${scrollProgress >= 0.62 && scrollProgress < 0.76
            ? 'opacity-100 translate-y-0 pointer-events-auto'
            : 'opacity-0 -translate-y-8 pointer-events-none'
            }`}
        >
          <div className="w-full max-w-[88rem] mx-auto px-6 sm:px-10 lg:px-14 xl:px-16">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
              {/* Left Column: Full Editorial Content */}
              <div className="lg:col-span-8 xl:col-span-7 space-y-7">
                {/* Supporting Headline */}
                <h2 className="text-3xl sm:text-4xl md:text-5xl lg:text-[2.65rem] xl:text-[3.15rem] 2xl:text-[3.45rem] font-black tracking-[-0.035em] text-white leading-[1.04] max-w-2xl lg:max-w-3xl">
                  <span className="block whitespace-normal sm:whitespace-nowrap">
                    Bridge Deep Graph Intelligence
                  </span>
                  <span className="block text-zinc-100 whitespace-normal sm:whitespace-nowrap">
                    with Rigorous Symbolic Solving.
                  </span>
                </h2>

                {/* Subheadline */}
                <p className="text-base sm:text-lg lg:text-[1.125rem] text-zinc-300/95 leading-[1.6] max-w-2xl font-normal">
                  {BRAND.subheadline}
                </p>

                {/* Action Buttons */}
                <div className="flex flex-wrap items-center gap-4 pt-2">
                  <button
                    type="button"
                    onClick={onStartAnalysis}
                    className="btn-signal group !py-3.5 !px-6 sm:!px-7 text-sm sm:text-base font-semibold shadow-lg shadow-rose-950/40"
                  >
                    <span>Start Binary Analysis</span>
                    <ArrowRight className="h-4 w-4 sm:h-5 sm:w-5 transition-transform group-hover:translate-x-1" />
                  </button>

                  <button
                    type="button"
                    onClick={onExploreDemo}
                    className="btn-secondary !py-3.5 !px-6 sm:!px-7 text-sm sm:text-base font-semibold"
                  >
                    <Terminal className="h-4 w-4 sm:h-5 sm:w-5 text-rose-400" />
                    <span>Explore Demo</span>
                  </button>
                </div>
              </div>

              {/* Right Column: Intentionally reserved for the 3D Hacker model */}
              <div className="hidden lg:block lg:col-span-4 xl:col-span-5 pointer-events-none" />
            </div>
          </div>
        </div>

        {/* =========================================================================
            SCENE 4 & 5: Mask Scroll Sequence — Monumental Dimensional Typography
            Primary: “EVERY BINARY HAS A STORY.”
            Secondary: “We uncover what the surface conceals.”
            (0.78 <= p < 0.91)
            ========================================================================= */}
        <div
          className={`absolute inset-0 z-20 flex flex-col justify-end pb-8 sm:pb-12 lg:justify-center lg:pb-0 transition-all duration-700 pointer-events-none ${scrollProgress >= 0.78 && scrollProgress < 0.91
            ? 'opacity-100 pointer-events-auto'
            : 'opacity-0 pointer-events-none'
            }`}
        >
          <div className="w-full max-w-[88rem] mx-auto px-6 sm:px-10 lg:px-14 xl:px-16">
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
              {/* Left Column: Monumental Dimensional Typography */}
              <div className="lg:col-span-8 xl:col-span-7 space-y-6">
                {/* Structural Category Tag */}
                <div
                  className="inline-flex items-center gap-2.5 px-3.5 py-1.5 rounded-full bg-rose-950/40 border border-rose-500/25 backdrop-blur-md transition-all duration-500"
                  style={{
                    opacity: Math.max(0, Math.min(1, (scrollProgress - 0.78) / 0.03)),
                    transform: `translateY(${(1 - Math.max(0, Math.min(1, (scrollProgress - 0.78) / 0.03))) * 14}px)`,
                  }}
                >
                  <span className="h-2 w-2 rounded-full bg-rose-500 animate-pulse" />
                  <span className="font-mono text-xs uppercase tracking-[0.25em] text-rose-300 font-semibold">
                    Structural Invariant Discovery
                  </span>
                </div>

                {/* Primary Monumental Headline: “EVERY BINARY HAS A STORY.” */}
                <h2
                  className="text-4xl sm:text-6xl lg:text-7xl xl:text-[5.25rem] font-black tracking-[-0.03em] uppercase leading-[0.96] text-white transition-all duration-500"
                  style={{
                    opacity: Math.max(0, Math.min(1, (scrollProgress - 0.80) / 0.04)),
                    transform: `translateY(${(1 - Math.max(0, Math.min(1, (scrollProgress - 0.80) / 0.04))) * 28}px)`,
                    textShadow:
                      '0 2px 24px rgba(0, 0, 0, 0.95), 0 0 40px rgba(240, 39, 63, 0.25), 0 1px 0 rgba(255, 255, 255, 0.25)',
                  }}
                >
                  <span className="block text-white">EVERY BINARY</span>
                  <span className="block bg-gradient-to-r from-white via-zinc-100 to-rose-400 bg-clip-text text-transparent">
                    HAS A STORY<span className="text-rose-500">.</span>
                  </span>
                </h2>

                {/* Secondary Line: “We uncover what the surface conceals.” */}
                <p
                  className="text-lg sm:text-xl lg:text-2xl font-light text-zinc-300/95 tracking-wide transition-all duration-500 max-w-xl leading-relaxed"
                  style={{
                    opacity: Math.max(0, Math.min(1, (scrollProgress - 0.83) / 0.04)),
                    transform: `translateY(${(1 - Math.max(0, Math.min(1, (scrollProgress - 0.83) / 0.04))) * 18}px)`,
                  }}
                >
                  “We uncover what the surface conceals.”
                </p>

                {/* Refined Architectural Proof Indicators */}
                <div
                  className="pt-3 flex flex-wrap items-center gap-6 font-mono text-xs text-zinc-400 transition-all duration-500"
                  style={{
                    opacity: Math.max(0, Math.min(1, (scrollProgress - 0.85) / 0.04)),
                  }}
                >
                  <div className="flex items-center gap-2">
                    <span className="h-1.5 w-1.5 rounded-sm bg-rose-500" />
                    <span className="text-zinc-200 font-semibold tracking-wider uppercase">GNN Topology Extraction</span>
                  </div>
                  <div className="h-3 w-px bg-zinc-800 hidden sm:block" />
                  <div className="flex items-center gap-2">
                    <span className="h-1.5 w-1.5 rounded-sm bg-rose-500" />
                    <span className="text-zinc-200 font-semibold tracking-wider uppercase">Z3 Constraint Proofs</span>
                  </div>
                </div>
              </div>

              {/* Right Column: Intentionally reserved for 3D White Mask & Sculptural Geometry */}
              <div className="hidden lg:block lg:col-span-4 xl:col-span-5 pointer-events-none" />
            </div>
          </div>
        </div>

        {/* =========================================================================
            SCENE 6 & PHYSICAL TRANSFORM INTO THE OPERATIONAL WORKBENCH
            (0.78 <= p <= 1.00)
            ========================================================================= */}
        {/* Transitional Structural Grid Layer */}
        <div
          className="absolute inset-0 pointer-events-none z-15 transition-opacity duration-700"
          style={{ opacity: bridgeProgress }}
        >
          {/* Subtle architectural framing lines */}
          <div className="absolute inset-x-8 top-12 border-t border-rose-500/20" />
          <div className="absolute inset-x-8 bottom-12 border-b border-rose-500/20" />
          <div className="absolute inset-y-12 left-8 border-l border-rose-500/20" />
          <div className="absolute inset-y-12 right-8 border-r border-rose-500/20" />
        </div>



        {/* Seamless bottom blend into Product Intro */}
        <div
          className="absolute bottom-0 left-0 right-0 h-28 pointer-events-none z-20 transition-all duration-500"
          style={{
            background:
              theme === 'light'
                ? `linear-gradient(to bottom, transparent, rgba(250, 250, 251, ${bridgeProgress}))`
                : `linear-gradient(to bottom, transparent, rgba(7, 8, 11, ${bgDarkness}))`,
          }}
        />
      </div>
    </div>
  );
};
