const deviceSize = {
  mobile360: '360px',
  mobile375: '375px',
  mobile450: '450px',
  tablet768: '768px',
  tablet1024: '1024px',
};

const device = {
  mobile360: `only screen and (max-width: ${deviceSize.mobile360})`,
  mobile375: `only screen and (max-width: ${deviceSize.mobile375})`,
  mobile450: `only screen and (max-width: ${deviceSize.mobile450})`,
  tablet768: `only screen and (max-width: ${deviceSize.tablet768})`,
  tablet1024: `only screen and (max-width: ${deviceSize.tablet1024})`,
};

const color = {
  main: '#00C4B8',
  sub: '#63EAB1',
  sub2: '#3CB4F7',
  dark: '#212121',
  gray1: '#333333',
  gray2: '#666666',
  gray3: '#A0A0A0',
  gray4: '#E5E5E5',
  gray5: '#F0F0F0',
  gray6: '#F8F8F8',
  white: '#FFFFFF',
  background: '#F5F4F8',
  warning: '#FA4B4B',
};

const font = {
  family: {
    display1: 'AppleSDGothicNeoB',
    display2: 'AppleSDGothicNeoB',
    display3: 'AppleSDGothicNeoB',
    display4: 'AppleSDGothicNeoB',
    focus1: 'AppleSDGothicNeoB',
    focus2: 'AppleSDGothicNeoB',
    focus3: 'AppleSDGothicNeoB',
    body1: 'AppleSDGothicNeoR',
    body2: 'AppleSDGothicNeoR',
    body3: 'AppleSDGothicNeoR',
    caption: 'AppleSDGothicNeoR',
    title: 'yg-jalnan',
  },
  weight: {
    display1: 700,
    display2: 700,
    display3: 700,
    display4: 700,
    focus1: 700,
    focus2: 700,
    focus3: 700,
    body1: 400,
    body2: 400,
    body3: 400,
    caption: 400,
    title: 700,
  },
  size: {
    display1: '24px',
    display2: '22px',
    display3: '20px',
    display4: '18px',
    focus1: '18px',
    focus2: '16px',
    focus3: '14px',
    body1: '18px',
    body2: '16px',
    body3: '14px',
    caption: '12px',
    title: '64px',
  },
  lineheight: {
    display1: '24px',
    display2: '22px',
    display3: '20px',
    display4: '18px',
    focus1: '18px',
    focus2: '16px',
    focus3: '14px',
    body1: '18px',
    body2: '16px',
    body3: '14px',
    caption: '12px',
    title: '24px',
  },
};

const shadow = {
  grid: `0px 4px 40px rgba(0, 0, 0, 0.1);`,
  card: `8px 4px 60px rgba(0, 0, 0, 0.08);`,
  button: `8px 4px 40px rgba(0, 0, 0, 0.3);`,
};

const Theme = {
  deviceSize,
  device,
  color,
  font,
  shadow,
};

export default Theme;
